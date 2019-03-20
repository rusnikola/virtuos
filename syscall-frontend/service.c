/**
 * VM-Syscalls
 * Copyright (c) 2012 Ruslan Nikolaev <rnikola@vt.edu>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "service.h"
#include "file.h"

#include <linux/irqreturn.h>
#include <linux/sched.h>
#include <linux/futex.h>
#include <linux/syscalls.h>
#include <asm/page.h>
#include <xen/events.h>
#include <asm/xen/page.h>
#include <asm/xen/hypercall.h>

#define SYSCALL_SERVICE_IS_TERMINATING(info)	\
	((volatile unsigned long) info->counter < SYSCALL_STATE_RUNNING)

static struct kmem_cache *expand_slab;
static struct kmem_cache *remove_slab;

static struct sccom_request *syscall_service_get_request(syscall_irq_info_t *info)
{
	while (1) {
		spin_lock(&info->main_lock);
		if (!RING_FULL(&info->main_ring))
			break;
		spin_unlock(&info->main_lock);
		if (SYSCALL_SERVICE_IS_TERMINATING(info))
			return NULL;
		yield();
	}
	return RING_GET_REQUEST(&info->main_ring, info->main_ring.req_prod_pvt);
}

static void syscall_service_put_request(syscall_irq_info_t *info)
{
	int notify;

	info->main_ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->main_ring, notify);
	spin_unlock(&info->main_lock);
	if (notify)
		notify_remote_via_irq(info->main_irq);
}

static struct vm_struct *syscall_alloc_shared(uint32_t gref, uint32_t domid,
	grant_handle_t *handle)
{
	struct vm_struct *area;
	struct gnttab_map_grant_ref map_op;
	pte_t *pte[2];

	area = alloc_vm_area(PAGE_SIZE, pte);
	if (!area)
		return NULL;

	map_op.host_addr = arbitrary_virt_to_machine(pte[0]).maddr;
	map_op.ref = gref;
	map_op.dom = domid;
	map_op.flags = GNTMAP_host_map | GNTMAP_contains_pte;

	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, &map_op, 1))
		goto error;
	if (map_op.status != GNTST_okay)
		goto error;

	*handle = map_op.handle;
	return area;

error:
	free_vm_area(area);
	return NULL;
}

static int syscall_free_shared(struct vm_struct *area, grant_handle_t handle)
{
	struct gnttab_unmap_grant_ref unmap_op;
	unsigned int level;

	unmap_op.host_addr = arbitrary_virt_to_machine(
		lookup_address((unsigned long) area->addr, &level)).maddr;
	unmap_op.handle = handle;
	unmap_op.dev_bus_addr = 0;

	if (HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, &unmap_op, 1))
		return -EFAULT;
	if (unmap_op.status != GNTST_okay)
		return -EFAULT;
	free_vm_area(area);
	return 0;
}

static int syscall_terminate_thread(void *_info)
{
	syscall_irq_info_t *info = _info;
	int rc;

	kthread_stop(info->request_thread);
	unbind_from_irqhandler(info->ring_irq, info);
	unbind_from_irqhandler(info->main_irq, info);
	unbind_from_irqhandler(info->wake_irq, info);

	syscall_free_shared(info->main_area, info->main_handle);
	syscall_free_shared(info->front_ring_area, info->front_ring_handle);
	syscall_free_shared(info->back_ring_area, info->back_ring_handle);
	rc = HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_DISCONNECT, info->sysid, 0);
	BUG_ON(rc != 0);
	notify_remote_via_irq(info->disconnect_irq);
	unbind_from_irqhandler(info->disconnect_irq, info);
	up(&info->disconnect_sem);

	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	set_current_state(TASK_RUNNING);
	return 0;
}

static void syscall_service_terminate(syscall_irq_info_t *info)
{
	unsigned long val;

	do {
		val = info->counter;
		if (val < SYSCALL_STATE_RUNNING)
			return;
	} while (!__sync_bool_compare_and_swap(&info->counter, val, val - SYSCALL_STATE_RUNNING));

	if (val - SYSCALL_STATE_RUNNING == SYSCALL_STATE_TERMINATED) {
		wake_up_process(info->terminate_thread);
	} else {
		wake_up_all(&info->add_queue);
		wake_up_all(&info->expand_queue);
		wake_up_all(&info->remove_queue);
	}
}

static void syscall_process_request(syscall_irq_info_t *info, int id, uint32_t tgid, uint32_t pid)
{
	struct task_struct *task;
	struct pid *pid_ptr;
	uint32_t real_tgid;

	SYSCALL_TRACE("process_request() %i for %u:%u\n", id, tgid, pid);
	pid_ptr = find_get_pid(pid);
	if (pid_ptr) {
		task = get_pid_task(pid_ptr, PIDTYPE_PID);
		if (task) {
			rcu_read_lock();
			real_tgid = task->tgid;
			rcu_read_unlock();
			if (real_tgid != tgid) /* Ignore (potentially) dangerous request */
				goto error;
			if ((unsigned int) id < SYSCALL_REQUEST_FD) { /* Event file descriptor */
				write_efd_task(id, task);
			} else if (id == SYSCALL_REQUEST_NOTIFY) {
				//wake_up_all(&task->rqueue_wq);
				wake_up(&task->rqueue_wq);
			}
error:
			put_task_struct(task);
		}
		put_pid(pid_ptr);
	}
	SYSCALL_TRACE("process_request() completed\n");
}

static int syscall_request_thread(void *_info)
{
	syscall_irq_info_t *info = _info;
	RING_IDX rc, rp;
	int entries;

	while (1) {
		wait_event(info->request_queue, kthread_should_stop() ||
			info->request_avail != 0);

		info->request_avail = 0;
		smp_wmb();

		do {
			if (kthread_should_stop())
				goto done;

			rp = info->front_ring.sring->rsp_prod;
			rmb();
			rc = info->front_ring.rsp_cons;

			while (rc != rp) {
				struct screq_response *rsp;

				rsp = RING_GET_RESPONSE(&info->front_ring, rc);
				syscall_process_request(info, rsp->id, rsp->tgid, rsp->pid);
				info->front_ring.rsp_cons = ++rc;
				if (kthread_should_stop())
					goto done;
			}

			RING_FINAL_CHECK_FOR_RESPONSES(&info->front_ring, entries);
		} while (entries);
	}

done:
	return 0;
}

static void syscall_process_main(syscall_irq_info_t *info, struct sccom_response *rsp)
{
	uint32_t num = rsp->num;
	uint32_t tgid = rsp->tgid;

	SYSCALL_TRACE("Received a response from remote domain: TGID=%u, NUM=%u\n", tgid, num);

	if (tgid != 0) /* Expand or remove operation */
	{
		unsigned long flags;
		struct syscall_expand_list *entry;
		struct syscall_remove_list *rentry;
		struct list_head *cur;

		if (num == 0) { /* Remove */
			spin_lock_irqsave(&info->remove_lock, flags);
			list_for_each(cur, &info->remove_list) {
				rentry = list_entry(cur, struct syscall_remove_list, list);
				if (rentry->tgid == tgid) {
					rentry->tgid = 0;
					break;
				}
			}
			spin_unlock_irqrestore(&info->remove_lock, flags);
			if (cur != NULL) {
				__sync_fetch_and_add(&info->remove_version, 1);
				wake_up_all(&info->remove_queue);
			}
			return;
		}

		if (num > SYSCALL_MAX_EXPAND_MAP_GREFS) { /* Invalid response */
			SYSCALL_ERROR("Ignoring invalid remote domain response with %u grefs\n", num);
			return;
		}

		spin_lock_irqsave(&info->expand_lock, flags);
		list_for_each(cur, &info->expand_list) {
			entry = list_entry(cur, struct syscall_expand_list, list);
			if (entry->tgid == tgid) {
				entry->num = num;
				memcpy(entry->grefs, rsp->grefs, num * sizeof(uint32_t));
				wmb();
				break;
			}
		}
		/* If not found, the task is probably deleted */
		spin_unlock_irqrestore(&info->expand_lock, flags);

		/* Notify waiting processes */
		if (cur != NULL) {
			__sync_fetch_and_add(&info->expand_version, 1);
			wake_up_all(&info->expand_queue);
		}
	} else if (num != 0) { /* Preallocted process */
		uint32_t i = 0;
		size_t index;

		if (num > SYSCALL_PREALLOC_PROCESSES) { /* Invalid response */
			SYSCALL_ERROR("Ignoring invalid remote domain response with %u prealloc entries\n", num);
			return;
		}

		do {
			/* Pop a free entry */
			index = syscall_stack_pop(info->processes.next, &info->processes.free_top, SYSCALL_PREALLOC_PROCESSES);
			BUG_ON(index == SYSCALL_ERROR_ENTRY);
			if (index == SYSCALL_NULL_ENTRY) {
				SYSCALL_ERROR("Leaking %u remote domain references\n", num);
				return;
			}
			info->processes.entry[index] = rsp->prealloc[i];
			/* Push an allocated entry */
			syscall_stack_push(info->processes.next, &info->processes.alloc_top, index);
			/* Notify waiting processes */
			wake_up_all(&info->add_queue);
		} while (++i != num);
	}
}

static irqreturn_t syscall_main_interrupt(int irq, void *dev_id)
{
	syscall_irq_info_t *info = dev_id;
	RING_IDX rc, rp;
	int responses;

	/* Read memory barrier is in syscall_service_enter() */
	if (syscall_service_enter(info))
		return IRQ_HANDLED;

	do {
		if (SYSCALL_SERVICE_IS_TERMINATING(info))
			goto done;

		rp = info->main_ring.sring->rsp_prod;
		rmb();
		rc = info->main_ring.rsp_cons;

		while (rc != rp) {
			struct sccom_response *rsp;

			rsp = RING_GET_RESPONSE(&info->main_ring, rc);
			syscall_process_main(info, rsp);
			info->main_ring.rsp_cons = ++rc;

			if (SYSCALL_SERVICE_IS_TERMINATING(info))
				goto done;
		}

		RING_FINAL_CHECK_FOR_RESPONSES(&info->main_ring, responses);
	} while (responses);

done:
	syscall_service_leave(info);
	return IRQ_HANDLED;
}

static irqreturn_t syscall_request_interrupt(int irq, void *dev_id)
{
	syscall_irq_info_t *info = dev_id;

	info->request_avail = 1;
	wake_up(&info->request_queue);
	return IRQ_HANDLED;
}

static irqreturn_t syscall_wake_interrupt(int irq, void *dev_id)
{
	return IRQ_HANDLED;
}

static irqreturn_t syscall_disconnect_interrupt(int irq, void *dev_id)
{
	syscall_irq_info_t *info = dev_id;
	syscall_service_terminate(info);
	return IRQ_HANDLED;
}

static void syscall_stack_init(syscall_prealloc_process_t *processes)
{
	syscall_ptr_t *top;
	size_t i;

	/* Allocated list */
	top = &processes->alloc_top;
	top->index = SYSCALL_NULL_ENTRY;
	top->stamp = 0;
	/* Free list */
	top = &processes->free_top;
	top->index = 0;
	top->stamp = 0;
	for (i = 0; i < SYSCALL_PREALLOC_PROCESSES - 1; i++)
		processes->next[i] = i + 1;
	processes->next[i] = SYSCALL_NULL_ENTRY;
	smp_mb();
}

int syscall_service_start(void)
{
	expand_slab = kmem_cache_create("syscall_expand_slab", sizeof(struct syscall_expand_list), 0, 0, NULL);
	if (!expand_slab) {
		SYSCALL_ERROR("Cannot create expand_slab\n");
		return -ENOMEM;
	}
	remove_slab = kmem_cache_create("syscall_remove_slab", sizeof(struct syscall_remove_list), 0, 0, NULL);
	if (!remove_slab) {
		kmem_cache_destroy(expand_slab);
		SYSCALL_ERROR("Cannot create remove_slab\n");
		return -ENOMEM;
	}
	return 0;
}

void syscall_service_exit(void)
{
	kmem_cache_destroy(remove_slab);
	kmem_cache_destroy(expand_slab);
}

int syscall_service_connect(syscall_irq_info_t *info, uint32_t sysid)
{
	char str[64];
	syscall_connect_t data;
	struct sccom_request *req;
	int notify, err;

	if (info->connected)
		return -EBUSY;

	info->sysid = sysid;
	sprintf(str, "syscall_terminate_thread_%u", sysid);
	info->terminate_thread = kthread_create(syscall_terminate_thread,
		info, str);
	if (IS_ERR(info->terminate_thread)) {
		err = PTR_ERR(info->terminate_thread);
		goto error9;
	}
	err = HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_PREPARE, sysid, &data);
	if (unlikely(err != 0)) {
		SYSCALL_ERROR("Cannot contact the remote domain\n");
		goto error8;
	}
	info->wake_gref = data.wake_gref;
	info->domid = data.domid;
	info->main_area = syscall_alloc_shared(data.main_gref, data.domid, &info->main_handle);
	if (info->main_area == NULL) {
		err = -ENOMEM;
		goto error7;
	}
	FRONT_RING_INIT(&info->main_ring, (struct sccom_sring *) info->main_area->addr, PAGE_SIZE);
	info->front_ring_area = syscall_alloc_shared(data.front_ring_gref, data.domid, &info->front_ring_handle);
	if (info->front_ring_area == NULL) {
		err = -ENOMEM;
		goto error6;
	}
	FRONT_RING_INIT(&info->front_ring, (struct screq_sring *) info->front_ring_area->addr, PAGE_SIZE);
	info->back_ring_area = syscall_alloc_shared(data.back_ring_gref, data.domid, &info->back_ring_handle);
	if (info->back_ring_area == NULL) {
		err = -ENOMEM;
		goto error5;
	}
	BACK_RING_INIT(&info->back_ring, (struct screq_sring *) info->back_ring_area->addr, PAGE_SIZE);
	syscall_stack_init(&info->processes);
	init_waitqueue_head(&info->add_queue);
	init_waitqueue_head(&info->expand_queue);
	init_waitqueue_head(&info->remove_queue);
	info->expand_version = 0;
	info->remove_version = 0;
	INIT_LIST_HEAD(&info->expand_list);
	INIT_LIST_HEAD(&info->remove_list);
	sema_init(&info->disconnect_sem, 0);
	info->main_irq = -1;
	info->ring_irq = -1;
	info->disconnect_irq = -1;
	info->wake_irq = -1;
	info->request_avail = 0;
	init_waitqueue_head(&info->request_queue);
	smp_mb();
	sprintf(str, "syscall_request_thread_%u", sysid);
	info->request_thread = kthread_create(syscall_request_thread,
		info, str);
	if (IS_ERR(info->request_thread)) {
		err = PTR_ERR(info->request_thread);
		goto error4;
	}
	wake_up_process(info->request_thread);
	sprintf(str, "syscall_main_irq_%u", sysid);
	err = bind_interdomain_evtchn_to_irqhandler(data.domid, data.main_port,
		syscall_main_interrupt, 0, str, info);
	if (unlikely(err < 0)) {
		SYSCALL_ERROR("Cannot bind (main) event channel\n");
		goto error3;
	}
	info->main_irq = err;
	smp_mb();
	sprintf(str, "syscall_request_irq_%u", sysid);
	err = bind_interdomain_evtchn_to_irqhandler(data.domid, data.ring_port,
		syscall_request_interrupt, 0, str, info);
	if (unlikely(err < 0)) {
		SYSCALL_ERROR("Cannot bind (ring) event channel\n");
		goto error2;
	}
	info->ring_irq = err;
	smp_mb();
	sprintf(str, "syscall_disconnect_irq_%u", sysid);
	err = bind_interdomain_evtchn_to_irqhandler(data.domid, data.disconnect_port, syscall_disconnect_interrupt, 0, str, info);
	if (unlikely(err < 0)) {
		SYSCALL_ERROR("Cannot bind (disconnect) event channel\n");
		goto error1;
	}
	info->disconnect_irq = err;
	smp_mb();
	sprintf(str, "syscall_wake_irq_%u", sysid);
	err = bind_interdomain_evtchn_to_irqhandler(data.domid, data.wake_port, syscall_wake_interrupt, 0, str, info);
	if (unlikely(err < 0)) {
		SYSCALL_ERROR("Cannot bind (wake) event channel\n");
		goto error0;
	}
	info->wake_irq = err;
	smp_mb();
	err = HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_CONNECT, sysid, &info->counter);
	if (unlikely(err != 0)) {
		SYSCALL_ERROR("Cannot connect to the remote domain\n");
		goto error_connect;
	}

	spin_lock(&info->main_lock);
	req = RING_GET_REQUEST(&info->main_ring, info->main_ring.req_prod_pvt);
	req->id = SYSCALL_ACTION_INIT;
	info->main_ring.req_prod_pvt++;
	RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&info->main_ring, notify);
	spin_unlock(&info->main_lock);
	if (notify)
		notify_remote_via_irq(info->main_irq);

	info->connected = 1;

	return 0;

error_connect:
	unbind_from_irqhandler(info->wake_irq, info);
error0:
	unbind_from_irqhandler(info->disconnect_irq, info);
error1:
	unbind_from_irqhandler(info->ring_irq, info);
error2:
	unbind_from_irqhandler(info->main_irq, info);
error3:
	kthread_stop(info->request_thread);
error4:
	syscall_free_shared(info->back_ring_area, info->back_ring_handle);
error5:
	syscall_free_shared(info->front_ring_area, info->front_ring_handle);
error6:
	syscall_free_shared(info->main_area, info->main_handle);
error7:
	HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_CANCEL, sysid, 0);
error8:
	kthread_stop(info->terminate_thread);
error9:
	return err;
}

int syscall_service_disconnect(syscall_irq_info_t *info)
{
	if (!info->connected)
		return -EINVAL;

	syscall_service_terminate(info);
	down(&info->disconnect_sem);
	kthread_stop(info->terminate_thread);
	info->connected = 0;
	return 0;
}

int syscall_service_add(syscall_irq_info_t *info, struct task_struct *task,
	syscall_add_t *data)
{
	struct task_struct *task_leader;
	struct sccom_request *req;
	uint32_t ptgid, id;
	const struct group_info *group_info;
	const struct cred *cred;
	size_t ngroups, i, num;
	size_t index, rqueue_idx;
	uint32_t *rqueue_gref;
	int rc = 0;

	if (syscall_service_enter(info))
		return -EFAULT;

	task_leader = task->group_leader;
	rqueue_gref = task_leader->rqueue_gref[info->sysid];
	for (rqueue_idx = 0; rqueue_idx < SYSCALL_QUEUE_PAGES; rqueue_idx++) {
		rqueue_gref[rqueue_idx] = gnttab_grant_foreign_access(info->domid,
			pfn_to_mfn(page_to_pfn(task_leader->rqueue_page + rqueue_idx)), 0);
		if ((int32_t) rqueue_gref[rqueue_idx] < 0) {
			rc = -EFAULT;
			goto error;
		}
	}

	rcu_read_lock();
	ptgid = rcu_dereference(task->real_parent)->tgid;
	rcu_read_unlock();

	cred = task->cred;
	group_info = cred->group_info;
	ngroups = group_info->ngroups;

	if (ngroups > SYSCALL_MAX_GROUPS) {
		rc = -EFAULT;
		goto error;
	}

	SYSCALL_TRACE("syscall_service_add(), %u\n", task->tgid);

	/* Obtain a grant reference */
	do {
		wait_event(info->add_queue, syscall_stack_check(&info->processes.alloc_top, SYSCALL_PREALLOC_PROCESSES) != SYSCALL_NULL_ENTRY || info->counter < SYSCALL_STATE_RUNNING);
		if (info->counter < SYSCALL_STATE_RUNNING) {
			rc = -EFAULT;
			goto error;
		}
		index = syscall_stack_pop(info->processes.next, &info->processes.alloc_top, SYSCALL_PREALLOC_PROCESSES);
		BUG_ON(index == SYSCALL_ERROR_ENTRY);
	} while (index == SYSCALL_NULL_ENTRY);

	data->gref[0] = info->wake_gref;
	memcpy(data->gref + 1, info->processes.entry[index].gref, SYSCALL_CALL_PAGES * sizeof(uint32_t));
	id = info->processes.entry[index].id;

	/* Release the entry */
	syscall_stack_push(info->processes.next, &info->processes.free_top, index);

	data->domid = info->domid;

	req = syscall_service_get_request(info);
	if (!req) {
		rc = -EFAULT;
		goto error;
	}

	req->id = SYSCALL_ACTION_ADD;
	req->tgid = task->tgid;
	memcpy(req->add.gref, rqueue_gref, SYSCALL_QUEUE_PAGES * sizeof(uint32_t));
	req->add.ptgid = ptgid;
	req->add.id = id;

	/* Copy capability info */
	req->add.cm.uid = cred->uid;
	req->add.cm.suid = cred->suid;
	req->add.cm.euid = cred->euid;
	req->add.cm.fsuid = cred->fsuid;
	req->add.cm.gid = cred->gid;
	req->add.cm.sgid = cred->sgid;
	req->add.cm.egid = cred->egid;
	req->add.cm.fsgid = cred->fsgid;
	req->add.cm.cap_inheritable = cred->cap_inheritable;
	req->add.cm.cap_permitted = cred->cap_permitted;
	req->add.cm.cap_effective = cred->cap_effective;
	req->add.cm.cap_bset = cred->cap_bset;
	req->add.cm.securebits = cred->securebits;
	req->add.cm.ngroups = ngroups;
	ngroups *= sizeof(gid_t);
	num = NGROUPS_PER_BLOCK * sizeof(gid_t);
	for (i = 0; ngroups != 0; i++) {
		if (num > ngroups)
			num = ngroups;
		memcpy(req->add.cm.groups + i * NGROUPS_PER_BLOCK, group_info->blocks[i], num);
		ngroups -= num;
	}
	syscall_service_put_request(info);

done:
	syscall_service_leave(info);
	SYSCALL_TRACE("syscall_service_add(), status %i\n", rc);
	return rc;

error:
	while (rqueue_idx != 0) {
		gnttab_end_foreign_access(rqueue_gref[--rqueue_idx], 0, 0);
	}
	goto done;
}

int syscall_service_remove(syscall_irq_info_t *info, uint32_t tgid)
{
	struct syscall_remove_list *entry;
	struct sccom_request *req;
	size_t rqueue_idx;
	uint32_t *rqueue_gref;
	size_t last_version;
	unsigned long flags;
	int rc = 0;

	if (syscall_service_enter(info))
		return -EFAULT;

	SYSCALL_TRACE("syscall_service_remove() for %u\n", tgid);

	entry = kmem_cache_alloc(remove_slab, GFP_KERNEL);
	if (!entry) {
		rc = -ENOMEM;
		goto error3;
	}
	entry->tgid = tgid;

	/* Add to the list */
	spin_lock_irqsave(&info->remove_lock, flags);
	list_add_tail(&entry->list, &info->remove_list);
	spin_unlock_irqrestore(&info->remove_lock, flags);

	/* Create a request */
	req = syscall_service_get_request(info);
	if (!req) {
		rc = -EFAULT;
		goto error1;
	}
	req->id = SYSCALL_ACTION_REMOVE;
	req->tgid = tgid;
	syscall_service_put_request(info);

	/* Wait for response. */
	while (1) {
		last_version = info->remove_version;
		spin_lock_irqsave(&info->remove_lock, flags);
		tgid = entry->tgid;
		if (!tgid)
			list_del(&entry->list);
		spin_unlock_irqrestore(&info->remove_lock, flags);
		if (!tgid)
			break;
		wait_event(info->remove_queue, info->remove_version != last_version || info->counter < SYSCALL_STATE_RUNNING);
		if (info->counter < SYSCALL_STATE_RUNNING) {
			rc = -EFAULT;
			goto error1;
		}
	}

	rqueue_gref = current->group_leader->rqueue_gref[info->sysid];
	for (rqueue_idx = 0; rqueue_idx < SYSCALL_QUEUE_PAGES; rqueue_idx++) {
		gnttab_end_foreign_access(rqueue_gref[rqueue_idx], 0, 0);
	}

error2:
	kmem_cache_free(remove_slab, entry);
error3:
	syscall_service_leave(info);
	SYSCALL_TRACE("syscall_service_remove(), status = %i\n", rc);
	return rc;

error1:
	spin_lock_irqsave(&info->remove_lock, flags);
	list_del(&entry->list);
	spin_unlock_irqrestore(&info->remove_lock, flags);
	goto error2;
}

int syscall_service_shrink_map(syscall_irq_info_t *info, uint32_t tgid,
	uint32_t num)
{
	struct sccom_request *req;
	int rc = 0;

	if (syscall_service_enter(info))
		return -EFAULT;

	/* Create a request. */
	req = syscall_service_get_request(info);
	if (!req) {
		rc = -EFAULT;
		goto error;
	}
	req->id = SYSCALL_ACTION_SHRINK_MAP;
	req->tgid = tgid;
	req->mem.num = num;
	syscall_service_put_request(info);

error:
	syscall_service_leave(info);
	return rc;
}

int syscall_service_expand_map(syscall_irq_info_t *info, uint32_t tgid,
	uint32_t *ptr, uint32_t num)
{
	struct sccom_request *req;
	struct syscall_expand_list *entry;
	size_t last_version;
	unsigned long flags;
	uint32_t entry_num;
	int rc = 0;

	if (syscall_service_enter(info))
		return -EFAULT;

	entry = kmem_cache_alloc(expand_slab, GFP_KERNEL);
	if (!entry) {
		rc = -ENOMEM;
		goto done2;
	}
	entry->tgid = tgid;
	entry->num = 0;

	/* Add to the list */
	spin_lock_irqsave(&info->expand_lock, flags);
	list_add_tail(&entry->list, &info->expand_list);
	spin_unlock_irqrestore(&info->expand_lock, flags);

	/* Create a request */
	req = syscall_service_get_request(info);
	if (!req) {
		rc = -EFAULT;
		goto done0;
	}
	req->id = SYSCALL_ACTION_EXPAND_MAP;
	req->tgid = tgid;
	req->mem.num = num;
	syscall_service_put_request(info);

	/* Wait for response */
	while (1) {
		last_version = info->expand_version;
		spin_lock_irqsave(&info->expand_lock, flags);
		entry_num = entry->num;
		if (entry_num != 0) {
			memcpy(ptr, entry->grefs, entry_num * sizeof(uint32_t));
			list_del(&entry->list);
		}
		spin_unlock_irqrestore(&info->expand_lock, flags);
		if (entry_num != 0) {
			if (entry_num != num || ptr[0] == -1)
				rc = -EFAULT;
			goto done1;
		}
		wait_event(info->expand_queue, info->expand_version != last_version || info->counter < SYSCALL_STATE_RUNNING);
		if (info->counter < SYSCALL_STATE_RUNNING) {
			rc = -EFAULT;
			goto done0;
		}
	}

done0:
	spin_lock_irqsave(&info->expand_lock, flags);
	list_del(&entry->list);
	spin_unlock_irqrestore(&info->expand_lock, flags);
done1:
	kmem_cache_free(expand_slab, entry);
done2:
	syscall_service_leave(info);
	return rc;
}

int syscall_service_cleanup(syscall_irq_info_t *info)
{
	syscall_service_disconnect(info);
	return HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_CLEANUP, info->sysid, 0);
}
