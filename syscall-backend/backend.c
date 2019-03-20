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

#include "handle.h"
#include "backend.h"
#include "file.h"

#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/init_task.h>
#include <linux/fdtable.h>
#include <linux/spinlock.h>
#include <linux/cred.h>
#include <linux/security.h>
#include <xen/grant_table.h>
#include <xen/page.h>
#include <xen/events.h>
#include <xen/balloon.h>
#include <asm/xen/hypercall.h>

static syscall_backend_info_t backend;
static DEFINE_SPINLOCK(notify_lock);

#define SYSCALL_FAULT_ENTRY         (size_t) (-4L)

static inline void syscall_queue_add(struct syscall_thread_group *data, struct syscall_queue *queue, struct pthread *thread)
{
	struct pthread *result;
	size_t idx, ret;

	idx = syscall_queue_dequeue_fault(queue->next, queue->entries,
		&queue->free_head, &queue->free_tail, &result,
		SYSCALL_MAX_PTHREADS, false);
	if ((ssize_t) idx < 0) {
		SYSCALL_ERROR("Ready queue failure (1)!\n");
		return;
	}
	if (__put_user(thread, &queue->entries[idx]))
		goto error_fault;
	ret = syscall_queue_enqueue_fault(queue->next, &queue->alloc_tail, idx,
		SYSCALL_MAX_PTHREADS, false);
	if (ret != 0) {
		SYSCALL_ERROR("Ready queue failure (2)!\n");
		return;
	}
	if (VOLATILE_READ_FAULT(queue->waiters) != 0) {
		syscall_backend_notify_done(SYSCALL_REQUEST_NOTIFY, data->tgid, data->tgid);
	}

error_fault: /* User program requested removal but
                some system calls are pending. */
	;
}

static void syscall_thread_free(struct work_struct *work)
{
	struct syscall_thread *thread = container_of(work, struct syscall_thread, rcu_work);

	put_task_struct(thread->task);
	kmem_cache_free(backend.thread_slab, thread);
}

static void syscall_thread_free_rcu(struct rcu_head *rcu)
{
	struct syscall_thread *thread = container_of(rcu, struct syscall_thread, rcu);

	queue_work(backend.wq, &thread->rcu_work);
}

void syscall_sync_cred(struct syscall_thread_group *data, const struct cred *cred)
{
	struct syscall_thread *thread;
	struct task_struct *task;

	rcu_read_lock();
	list_for_each_entry_rcu(thread, &data->threads, list) {
		task = thread->task;
		if (task == current)
			continue;
		task_lock(task);
		get_cred(cred); /* Objective reference */
		if (commit_task_creds((struct cred *) cred, task) != 0) {
			SYSCALL_ERROR("Cannot synchronize creds with %u:%u, "
				"user process %u\n", task->tgid, task->pid, data->tgid);
		}
		task_unlock(task);
	}
	rcu_read_unlock();
	put_cred(cred);
}

static struct page *syscall_alloc_shared_page(uint32_t *gref)
{
	uint32_t ref;
	struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return NULL;
	ref = gnttab_grant_foreign_access(DOM0, pfn_to_mfn(page_to_pfn(page)), 0);
	if ((int32_t) ref < 0) {
		__free_page(page);
		return NULL;
	}
	*gref = ref;
	return page;
}

static void *syscall_alloc_shared(uint32_t *gref)
{
	struct page *page = syscall_alloc_shared_page(gref);
	if (!page)
		return NULL;
	return (void *) pfn_to_kaddr(page_to_pfn(page));
}

static inline void syscall_free_shared_page(uint32_t gref, struct page *page)
{
	/* It will execute free_page() as well */
	gnttab_end_foreign_access(gref, 0, (unsigned long) pfn_to_kaddr(page_to_pfn(page)));
}

static inline void syscall_free_shared(uint32_t gref, void *addr)
{
	/* It will execute free_page() as well */
	gnttab_end_foreign_access(gref, 0, (unsigned long) addr);
}

static void syscall_stack_init(syscall_page_t *page)
{
	syscall_ptr_t *top;
	size_t i;

	/* Allocated list */
	top = &page->alloc_top;
	top->index = 0;
	top->stamp = 0;
	/* Free list */
	top = &page->free_top;
	top->index = 1;
	top->stamp = 0;
	for (i = 1; i < SYSCALL_MAX_ENTRIES - 1; i++)
		page->next[i] = i + 1;
	page->next[0] = SYSCALL_NULL_ENTRY;
	page->next[i] = SYSCALL_NULL_ENTRY;
	/* Init call */
	page->entry[0].id = __NRR_syscall_service_init;
	page->entry[0].seq_num = 0;
	page->entry[0].signal = 0;
	/* task_id is not known yet */
	mb();
}

void syscall_backend_notify_done(int id, uint32_t tgid, uint32_t pid)
{
	struct screq_response *rsp;
	int notify;

	while (1) {
		spin_lock(&notify_lock);
		if (!RING_FULL_RSP(&backend.back_ring))
			break;
		spin_unlock(&notify_lock);
		if (kthread_should_stop())
			return;
		yield();
	}

	rsp = RING_GET_RESPONSE(&backend.back_ring, backend.back_ring.rsp_prod_pvt);
	rsp->id = id;
	rsp->tgid = tgid;
	rsp->pid = pid;
	backend.back_ring.rsp_prod_pvt++;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&backend.back_ring, notify);
	spin_unlock(&notify_lock);
	if (notify) {
		notify_remote_via_irq(backend.ring_irq);
	}
}

static size_t syscall_wake_groups(struct syscall_thread_group *active_data)
{
	syscall_wake_page_t *wake_page = backend.wake_page;
	syscall_page_t *page;
	struct syscall_thread_group *data;
	unsigned long num;
	size_t index, count = 0;
	uint64_t running_threads;

	if (wake_page->running_threads >> 33) {
		rcu_read_lock();
		list_for_each_entry_rcu(data, &backend.thread_groups, list) {
			if (data == active_data || !(data->num_queue & ~SYSCALL_QUEUE_STOP))
				continue;
			page = data->page;
			index = syscall_stack_pop(page->next, &page->alloc_top, SYSCALL_MAX_ENTRIES);
			if ((ssize_t) index >= 0) {
				do {
					num = data->num_queue;
					if (!(num & ~SYSCALL_QUEUE_STOP)) {
						syscall_stack_push(page->next, &page->alloc_top, index);
						goto next;
					}
				} while (!__sync_bool_compare_and_swap(&data->num_queue, num, num - SYSCALL_QUEUE_STEP));
				running_threads = __sync_fetch_and_add(&wake_page->running_threads, 0xFFFFFFFE00000001ULL);
				/* Insert into the prefetch stack */
				syscall_stack_push(page->next, &data->fetch_top, index);
				__sync_fetch_and_add(&data->num_wakes, 1);
				wake_up(&data->queue);
				count++;
			}
			next: ;
		}
		rcu_read_unlock();
	}
	return count;
}

static void syscall_sfn_sleep(void)
{
	syscall_wake_page_t *wake_page = backend.wake_page;
	syscall_page_t *page;
	struct syscall_thread_group *data, *last_data;
	unsigned long num;
	size_t index;
	uint64_t running_threads;

	preempt_disable();
	do {
		while (((running_threads = wake_page->running_threads) >> 33) && ((running_threads & 0x1FFFFFFFFULL) <= MIN_RUNNING_THREADS)) {
			rcu_read_lock();
			last_data = NULL;
			/* Try to find a thread that has something to do */
			list_for_each_entry_rcu(data, &backend.thread_groups, list) {
				if (!(data->num_queue & ~SYSCALL_QUEUE_STOP))
					continue;
				last_data = data;
				page = data->page;
				index = syscall_stack_pop(page->next, &page->alloc_top, SYSCALL_MAX_ENTRIES);
				if ((ssize_t) index >= 0) {
					do {
						num = data->num_queue;
						if (!(num & ~SYSCALL_QUEUE_STOP)) {
							syscall_stack_push(page->next, &page->alloc_top, index);
							goto next;
						}
					} while (!__sync_bool_compare_and_swap(&data->num_queue, num, num - SYSCALL_QUEUE_STEP));
					__sync_fetch_and_sub(&wake_page->running_threads, 0x200000000ULL);
					syscall_stack_push(page->next, &data->fetch_top, index);
					__sync_fetch_and_add(&data->num_wakes, 1);
					wake_up(&data->queue);
					rcu_read_unlock();
					preempt_enable();
					return;
				}
				next: ;
			}
			/* Wake up any sleeping thread */
			if (last_data != NULL) {
				do {
					num = last_data->num_queue;
					if (!(num & ~SYSCALL_QUEUE_STOP))
						goto again;
				} while (!__sync_bool_compare_and_swap(&last_data->num_queue, num, num - SYSCALL_QUEUE_STEP));
				__sync_fetch_and_sub(&wake_page->running_threads, 0x200000000ULL);
				__sync_fetch_and_add(&last_data->num_wakes, 1);
				wake_up(&last_data->queue);
				rcu_read_unlock();
				preempt_enable();
				return;
			}
again:
			rcu_read_unlock();
		}
	} while (!__sync_bool_compare_and_swap(&wake_page->running_threads, running_threads, running_threads - 1));
	preempt_enable();
}

static void syscall_sfn_wake(void)
{
	__sync_fetch_and_add(&backend.wake_page->running_threads, 1);
}

static size_t syscall_pop_sleep(syscall_page_t *page, struct syscall_thread_group *data, size_t *yield_count)
{
	syscall_wake_page_t *wake_page = backend.wake_page;
	uint64_t running_threads, new_running_threads;
	unsigned long num;
	size_t index, next_index;

	preempt_disable();
	syscall_wake_groups(data);
	/* Check before yielding */
	index = syscall_stack_pop(page->next, &page->alloc_top, SYSCALL_MAX_ENTRIES);
	if ((ssize_t) index >= 0) {
		while (data->num_queue & ~SYSCALL_QUEUE_STOP) {
			next_index = syscall_stack_pop(page->next, &page->alloc_top, SYSCALL_MAX_ENTRIES);
			if ((ssize_t) next_index < 0)
				break;
			do {
				num = data->num_queue;
				if (!(num & ~SYSCALL_QUEUE_STOP)) {
					syscall_stack_push(page->next, &page->alloc_top, next_index);
					goto skip;
				}
			} while (!__sync_bool_compare_and_swap(&data->num_queue, num, num - SYSCALL_QUEUE_STEP));
			__sync_fetch_and_add(&wake_page->running_threads, 0xFFFFFFFE00000001ULL);
			/* Insert into the prefetch stack */
			syscall_stack_push(page->next, &data->fetch_top, next_index);
			__sync_fetch_and_add(&data->num_wakes, 1);
			wake_up(&data->queue);
		}
skip:
		preempt_enable();
		return index;
	}

	while (1) {
		running_threads = wake_page->running_threads;
		if ((running_threads & 0x1FFFFFFFFULL) <= MIN_RUNNING_THREADS) {
			if (*yield_count != 0) {
				preempt_enable();
				(*yield_count)--;
				yield();
				return SYSCALL_NULL_ENTRY;
			}
			if (!__sync_bool_compare_and_swap(&wake_page->running_threads, running_threads, running_threads + SYSCALL_WAKE_REQUESTED))
				continue;
			preempt_enable();
			*yield_count = SYSCALL_YIELD_COUNT;
			return SYSCALL_REPEAT_ENTRY;
		}
		new_running_threads = (running_threads - 1) + 0x200000000ULL;
		if (__sync_bool_compare_and_swap(&wake_page->running_threads, running_threads, new_running_threads))
			break;
	}

	do {
		num = data->num_queue;
		if (num & SYSCALL_QUEUE_STOP) {
			/* Decrement waiting threads in queues and increment
				number of threads. */
			__sync_fetch_and_add(&wake_page->running_threads, 0xFFFFFFFE00000001ULL);
			preempt_enable();
			return SYSCALL_NULL_ENTRY;
		}
	} while (!__sync_bool_compare_and_swap(&data->num_queue, num, num + SYSCALL_QUEUE_STEP));
	preempt_enable();

	/* Sleep */
wait:
	wait_event_nosfn(data->queue, data->num_wakes != 0);
	do {
		num = data->num_wakes;
		if (num == 0)
			goto wait;
	} while (!__sync_bool_compare_and_swap(&data->num_wakes, num, num - 1));

	return syscall_stack_pop(page->next, &data->fetch_top, SYSCALL_MAX_ENTRIES);
}

static int syscall_map_rqueue(struct syscall_thread_group *data)
{
	struct gnttab_map_grant_ref map_ops[SYSCALL_QUEUE_PAGES];
	size_t idx;

	data->rqueue_area = alloc_vm_area(PAGE_SIZE * SYSCALL_QUEUE_PAGES, NULL);
	if (!data->rqueue_area) {
		SYSCALL_ERROR("Cannot map ready queue (0)!\n");
		return -EINVAL;
	}
	if (alloc_xenballooned_pages(SYSCALL_QUEUE_PAGES, data->rqueue_pages, false)) {
		SYSCALL_ERROR("Cannot map ready queue (1)!\n");
		goto error3;
	}
	for (idx = 0; idx < SYSCALL_QUEUE_PAGES; idx++) {
		map_ops[idx].host_addr = page_to_phys(data->rqueue_pages[idx]);
		map_ops[idx].ref = data->rqueue_gref[idx];
		map_ops[idx].dom = DOM0;
		map_ops[idx].flags = GNTMAP_host_map;
		map_ops[idx].status = GNTST_general_error;
	}
	if (HYPERVISOR_grant_table_op(GNTTABOP_map_grant_ref, map_ops, SYSCALL_QUEUE_PAGES)) {
		SYSCALL_ERROR("Cannot map ready queue (2)!\n");
		goto error2;
	}
	for (idx = 0; idx < SYSCALL_QUEUE_PAGES; idx++) {
		data->rqueue_unmap[idx].host_addr = map_ops[idx].host_addr;
		data->rqueue_unmap[idx].handle = map_ops[idx].handle;
		data->rqueue_unmap[idx].dev_bus_addr = 0;
	}
	for (idx = 0; idx < SYSCALL_QUEUE_PAGES; idx++) {
		if (map_ops[idx].status != GNTST_okay) {
			SYSCALL_ERROR("Cannot map ready queue (3) %u!\n", map_ops[idx].ref);
			goto error1;
		}
	}
	if (map_kernel_range((unsigned long) data->rqueue_area->addr, SYSCALL_QUEUE_PAGES * PAGE_SIZE, PAGE_SHARED, data->rqueue_pages) != SYSCALL_QUEUE_PAGES) {
		SYSCALL_ERROR("Cannot map ready queue (4)!\n");
		goto error1;
	}
#if 0
	for (idx = 0; idx < SYSCALL_QUEUE_PAGES; idx++) {
		if (m2p_add_override(PFN_DOWN(map_ops[idx].dev_bus_addr), data->rqueue_pages[idx], NULL))
			SYSCALL_ERROR("m2p_add_override failed!\n");
	}
#endif
	data->rqueue = (struct syscall_queue *) data->rqueue_area->addr;
	return 0;

error1:
	for (idx = 0; idx < SYSCALL_QUEUE_PAGES; idx++) {
		if (map_ops[idx].status == GNTST_okay) {
			HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, data->rqueue_unmap + idx, 1);
		}
	}
error2:
	free_xenballooned_pages(SYSCALL_QUEUE_PAGES, data->rqueue_pages);
error3:
	free_vm_area(data->rqueue_area);
	return -EINVAL;
}

static void syscall_unmap_rqueue(struct syscall_thread_group *data)
{
	int rc;

	unmap_kernel_range((unsigned long) data->rqueue, SYSCALL_QUEUE_PAGES * PAGE_SIZE);
	rc = HYPERVISOR_grant_table_op(GNTTABOP_unmap_grant_ref, data->rqueue_unmap, SYSCALL_QUEUE_PAGES);
	WARN_ON(rc);
#if 0
	for (idx = 0; idx < SYSCALL_QUEUE_PAGES; idx++) {
		if (m2p_remove_override(virt_to_page(data->rqueue_unmap[idx].host_addr), false))
			SYSCALL_ERROR("m2p_remove_override failed!\n");
	}
#endif
}

static int syscall_thread(void *_thread)
{
	struct syscall_thread *thread = _thread, *next_thread;
	struct syscall_thread_group *data = thread->data;
	syscall_page_t *page = data->page;
	struct syscall_queue *rqueue = data->rqueue;
	syscall_entry_t *entry;
	size_t index = SYSCALL_NULL_ENTRY;
	long result;
	unsigned long flags;
	unsigned int id;
	uint32_t task_id;
	size_t yield_count = SYSCALL_YIELD_COUNT;
	mm_segment_t fs = MAKE_MM_END_START((unsigned long) data->page + SYSCALL_TOTAL_SHARED_PAGES * PAGE_SIZE, (unsigned long) data->page);

	set_fs(fs); 

	__sync_fetch_and_add(&backend.wake_page->running_threads, 1);

	preempt_disable();
	current->sfn_sleep = &syscall_sfn_sleep;
	current->sfn_wake = &syscall_sfn_wake;
	preempt_enable();

	while (!(data->num_queue & SYSCALL_QUEUE_STOP) || index == SYSCALL_REPEAT_ENTRY) {
		index = syscall_pop_sleep(page, data, &yield_count);
		if ((ssize_t) index < 0)
			continue;
		if (atomic_dec_and_test(&data->idle_counter)) {
			/* Create a new thread */
			next_thread = kmem_cache_alloc(backend.thread_slab, GFP_KERNEL);
			if (next_thread) {
				next_thread->data = data;
				next_thread->task_id = 0;
				INIT_WORK(&next_thread->rcu_work, syscall_thread_free);
				next_thread->task = kthread_syscall_create(syscall_thread, next_thread, CLONE_FS | CLONE_FILES | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, data->name);
				if (IS_ERR(next_thread->task)) {
					kmem_cache_free(backend.thread_slab, next_thread);
					SYSCALL_ERROR("Cannot create a worker thread for user process "
						"%u, %li\n", data->tgid, PTR_ERR(next_thread->task));
				} else {
					smp_mb__before_atomic_inc();
					atomic_inc(&data->idle_counter);
					smp_mb__after_atomic_inc();
					get_task_struct(next_thread->task);
					spin_lock(&data->lock);
					list_add_tail_rcu(&next_thread->list, &data->threads);
					spin_unlock(&data->lock);
					wake_up_process(next_thread->task);
				}
			} else {
				SYSCALL_ERROR("Cannot allocate a worker thread entry\n");
			}
		}
		entry = &page->entry[index];
		task_id = entry->task_id;
#ifndef DISABLE_POSIX_INTERRUPT
		spin_lock(&data->lock);
		thread->task_id = task_id;
		thread->seq_num = entry->seq_num;
		spin_unlock(&data->lock);
		/* Set pending signal now */
		smp_rmb();
		if (unlikely(entry->signal)) {
			spin_lock_irqsave(&thread->task->sighand->siglock, flags);
			set_tsk_thread_flag(thread->task, TIF_SIGPENDING);
			spin_unlock_irqrestore(&thread->task->sighand->siglock, flags);
		}
#endif
		id = entry->id & ~SYSCALL_ENTRY_RQUEUE;
		result = syscall_handle(data, entry, id);
		if (result == -ERESTARTSYS || result == -ERESTARTNOHAND ||
			result == -ERESTARTNOINTR || result == -ERESTART_RESTARTBLOCK) {
			result = -EINTR;
		}
		syscall_entry_result_lower(entry) = result;
#ifndef DISABLE_POSIX_INTERRUPT
		/* Discard further signals */
		spin_lock(&data->lock);
		thread->task_id = 0;
		spin_unlock(&data->lock);
		/* Clear all pending signals */
		spin_lock_irqsave(&thread->task->sighand->siglock, flags);
		clear_tsk_thread_flag(thread->task, TIF_SIGPENDING);
		spin_unlock_irqrestore(&thread->task->sighand->siglock, flags);
#endif
		/* Put to the queue only if the other end requested to (xchg) */
		if ((__sync_lock_test_and_set(&entry->id, SYSCALL_ENTRY_DONE) & SYSCALL_ENTRY_RQUEUE) && rqueue != NULL) {
			syscall_queue_add(data, rqueue, entry->pd);
		}
		smp_mb__before_atomic_inc();
		atomic_inc(&data->idle_counter);
		smp_mb__after_atomic_inc();
	}

	syscall_sfn_sleep();

	preempt_disable();
	current->sfn_sleep = NULL;
	current->sfn_wake = NULL;
	preempt_enable();

	/* Wait until the thread is terminated */
	set_current_state(TASK_UNINTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_UNINTERRUPTIBLE);
	}
	set_current_state(TASK_RUNNING);

	/* Remove the thread from the list */
	spin_lock(&data->lock);
	list_del_rcu(&thread->list);
	spin_unlock(&data->lock);

	return 0;
}

static int syscall_initial_thread(void *_thread)
{
	struct syscall_thread *thread = _thread;
	syscall_map_rqueue(thread->data);
	return syscall_thread(thread);
}

static void syscall_thread_group_free(struct work_struct *work)
{
	struct syscall_thread_group *data = container_of(work, struct syscall_thread_group, rcu_work);
	size_t i;

	if (data->rqueue) {
		free_xenballooned_pages(SYSCALL_QUEUE_PAGES, data->rqueue_pages);
		free_vm_area(data->rqueue_area);
	}
	unmap_kernel_range((unsigned long) data->page, SYSCALL_CALL_PAGES * PAGE_SIZE);
	for (i = 0; i < SYSCALL_CALL_PAGES; i++)
		syscall_free_shared_page(data->map_gref[i], data->map_pages[i]);
	free_vm_area(data->map_area);
	kmem_cache_free(backend.thread_group_slab, data);
}

static void syscall_thread_group_free_rcu(struct rcu_head *rcu)
{
	struct syscall_thread_group *data = container_of(rcu, struct syscall_thread_group, rcu);

	queue_work(backend.wq, &data->rcu_work);
}

static struct syscall_thread_group *syscall_thread_group_alloc(void)
{
	struct syscall_thread_group *data;
	struct vm_struct *area;
	size_t i;

	data = kmem_cache_alloc(backend.thread_group_slab, GFP_KERNEL);
	if (!data)
		return NULL;
	data->rqueue = NULL;
	/* Allocate large VM area */
	area = alloc_vm_area(PAGE_SIZE * SYSCALL_TOTAL_SHARED_PAGES, NULL);
	if (!area)
		goto error2;
	for (i = 0; i < SYSCALL_CALL_PAGES; i++) {
		data->map_pages[i] = syscall_alloc_shared_page(&data->map_gref[i]);
		if (data->map_pages[i] == NULL) {
			SYSCALL_ERROR("Cannot grant a syscall page\n");
			goto error1;
		}
	}
	if (map_kernel_range((unsigned long) area->addr, SYSCALL_CALL_PAGES * PAGE_SIZE, PAGE_SHARED, data->map_pages) != SYSCALL_CALL_PAGES)
		goto error1;
	data->map_area = area;
	data->map_pos = SYSCALL_CALL_PAGES;
	INIT_LIST_HEAD(&data->threads);
	INIT_WORK(&data->rcu_work, syscall_thread_group_free);
	spin_lock_init(&data->lock);
	init_waitqueue_head(&data->queue);
	data->num_queue = 0;
	data->num_wakes = 0;
	data->page = (syscall_page_t *) area->addr;
	syscall_stack_init(data->page);
	data->fetch_top.index = SYSCALL_NULL_ENTRY;
	data->fetch_top.stamp = 0;
	return data;

error1:
	while (i != 0) {
		--i;
		syscall_free_shared_page(data->map_gref[i], data->map_pages[i]);
	}
	free_vm_area(area);
error2:
	kmem_cache_free(backend.thread_group_slab, data);
	return NULL;
}

static int syscall_thread_group_do_expand_map(struct syscall_thread_group *data, grant_ref_t *grefs, uint32_t num)
{
	struct page **pages;
	grant_ref_t *grants;
	uint32_t i, ref;

	if (num > SYSCALL_MAX_EXPAND_MAP_GREFS
	    || num > SYSCALL_TOTAL_SHARED_PAGES - data->map_pos)
		return -EINVAL;

	if (num != 0)
	{
		pages = data->map_pages + data->map_pos;
		grants = data->map_gref + data->map_pos;
		for (i = 0; i < num; i++) {
			pages[i] = syscall_alloc_shared_page(&ref);
			if (pages[i] == NULL)
				goto error;
			grants[i] = grefs[i] = ref;
		}
		if (map_kernel_range((unsigned long) data->page + data->map_pos * PAGE_SIZE, num * PAGE_SIZE, PAGE_SHARED, pages) != num)
			goto error;
		data->map_pos += num;
	}
	return 0;

error:
	SYSCALL_ERROR("Cannot allocate or grant mapping pages\n");
	while (i != 0) {
		--i;
		syscall_free_shared_page(grants[i], pages[i]);
	}
	return -EFAULT;
}

static int syscall_thread_group_do_shrink_map(struct syscall_thread_group *data, uint32_t num)
{
	struct page **pages;
	grant_ref_t *grants;
	uint32_t i;

	if (num > data->map_pos - SYSCALL_CALL_PAGES)
		return -EINVAL;

	if (num != 0)
	{
		data->map_pos -= num;
		pages = data->map_pages + data->map_pos;
		grants = data->map_gref + data->map_pos;
		/* Unmap pages */
		unmap_kernel_range((unsigned long) data->page + data->map_pos * PAGE_SIZE, num * PAGE_SIZE);
		/* Finish grant access */
		for (i = 0; i < num; i++) {
			syscall_free_shared_page(grants[i], pages[i]);
		}
	}
	return 0;
	
}

static int syscall_thread_group_expand_map(uint32_t tgid, grant_ref_t *grefs,
	uint32_t num)
{
	struct syscall_thread_group *data;
	int err = -ESRCH;

	SYSCALL_TRACE("thread_group_expand() for tgid %u, num %u\n", tgid, num);
	rcu_read_lock();
	list_for_each_entry_rcu(data, &backend.thread_groups, list) {
		if (data->tgid == tgid) {
			err = syscall_thread_group_do_expand_map(data, grefs, num);
			break;
		}
	}
	rcu_read_unlock();
	SYSCALL_TRACE("thread_group_expand(), status %i\n", err);
	return err;
}

static int syscall_thread_group_shrink_map(uint32_t tgid, uint32_t num)
{
	struct syscall_thread_group *data;
	int err = -ESRCH;

	SYSCALL_TRACE("thread_group_shrink() for tgid %u, num %u\n", tgid, num);
	rcu_read_lock();
	list_for_each_entry_rcu(data, &backend.thread_groups, list) {
		if (data->tgid == tgid) {
			err = syscall_thread_group_do_shrink_map(data, num);
			break;
		}
	}
	rcu_read_unlock();
	SYSCALL_TRACE("thread_group_shrink(), status %i\n", err);
	return err;
}

static int syscall_thread_group_add(struct syscall_thread_group *data,
	uint32_t tgid, uint32_t ptgid, struct cred_move *cm)
{
	struct files_struct *old_files, *new_files;
	struct syscall_thread *thread;
	struct syscall_thread_group *entry;
	struct task_struct *task, *parent = &init_task;
	struct cred *cred;
	int err, parent_init_efd = -1;

	SYSCALL_TRACE("thread_group_add() for %u, parent %u\n", tgid, ptgid);
	thread = kmem_cache_alloc(backend.thread_slab, GFP_KERNEL);
	if (!thread)
		return -ENOMEM;
	thread->task_id = 0;
	INIT_WORK(&thread->rcu_work, syscall_thread_free);
	list_add_tail_rcu(&thread->list, &data->threads);
	atomic_set(&data->idle_counter, 1);
	data->tgid = tgid;
	snprintf(data->name, sizeof(data->name), "syscall_thread [%u]", tgid);
	thread->data = data;
	task = kthread_syscall_create(syscall_initial_thread, thread, CLONE_FS | CLONE_FILES | SIGCHLD, data->name);
	if (IS_ERR(task)) {
		SYSCALL_ERROR("Cannot create an initial worker thread for thread "
			"group %u\n", data->tgid);
		err = PTR_ERR(task);
		goto error5;
	}
	get_task_struct(task);
	thread->task = task;

	/* Only one active thread is writing, no need to protect it. */
	list_for_each_entry(entry, &backend.thread_groups, list) {
		if (entry->tgid == tgid) {
			SYSCALL_ERROR("Process %u is already in the list\n", tgid);	
			err = -EFAULT;
			goto error4;
		}
	}

	rcu_read_lock();
	list_for_each_entry(entry, &backend.thread_groups, list) {
		if (entry->tgid == ptgid) {
			SYSCALL_TRACE("thread_group_add() located parent %u\n", ptgid);
			thread = list_first_entry_rcu(&entry->threads, struct syscall_thread, list);
			if (&thread->list != &entry->threads) {
				parent = thread->task;
				parent_init_efd = entry->init_efd;
				cm = NULL;
			}
			break;
		}
	}
	get_task_struct(parent);
	rcu_read_unlock();

	task_lock(parent);
	cred = prepare_task_creds(parent, cm);
	if (!cred) {
		err = -ENOMEM;
		goto error3;
	}
	old_files = parent->files;
	if (!old_files) {
		new_files = NULL;
	} else {
		new_files = dup_fd(old_files, &err);
		if (!new_files)
			goto error2;
	}
	task_unlock(parent);
	put_task_struct(parent);
	parent = NULL;

	task_lock(task);
	exit_creds(task);
	if (do_copy_creds(task, 0, cred) != 0) {
		err = -EFAULT;
		task_unlock(task);
		goto error1;
	}
	if (task->files)
		put_files_struct(task->files);
	task->files = new_files;
	task_unlock(task);

	data->init_efd = -1;
	data->page->entry[0].args[0] = parent_init_efd;
	list_add_tail_rcu(&data->list, &backend.thread_groups);
	wake_up_process(task);

	SYSCALL_TRACE("thread_group_add(), status 0\n");
	return 0;

error1:
	if (new_files)
		put_files_struct(new_files);
error2:
	abort_creds(cred);
error3:
	if (parent != NULL) {
		task_unlock(parent);
		put_task_struct(parent);
	}
error4:
	kthread_syscall_stop(thread->task);
	put_task_struct(thread->task);
error5:
	kmem_cache_free(backend.thread_slab, thread);
	SYSCALL_TRACE("thread_group_add(), status %i\n", err);
	return err;
}

static void syscall_prepare_terminate(struct syscall_thread_group *data)
{
	unsigned long num;

	/* Request termination (preemption is disabled by the spin lock) */
	do {
		num = data->num_queue;
	} while (!__sync_bool_compare_and_swap(&data->num_queue, num, SYSCALL_QUEUE_STOP));
	num /= SYSCALL_QUEUE_STEP;
	__sync_fetch_and_add(&backend.wake_page->running_threads, ((uint64_t) -num << 33) | num);
	__sync_fetch_and_add(&data->num_wakes, num);
	/* Wake up everybody */
	wake_up_all(&data->queue);
}

static int syscall_thread_group_remove(uint32_t tgid)
{
	struct syscall_thread *thread;
	struct syscall_thread_group *data;
	int ret = -ESRCH;

	SYSCALL_TRACE("thread_group_remove() for %i", tgid);
	list_for_each_entry(data, &backend.thread_groups, list) {
		if (data->tgid == tgid) {
			list_del_rcu(&data->list);
			break;
		}
	}

	if (&data->list != &backend.thread_groups) { /* Found */
		syscall_prepare_terminate(data);
		/* We cannot hold a lock while stopping a thread, as it can request
		   this lock too. */
		while (1) {
			thread = list_first_entry_rcu(&data->threads, struct syscall_thread, list);
			if (&thread->list == &data->threads)
				break;
			kthread_syscall_stop(thread->task);
			call_rcu(&thread->rcu, syscall_thread_free_rcu);
		}
		syscall_thread_group_do_shrink_map(data, data->map_pos - SYSCALL_CALL_PAGES);
		syscall_unmap_rqueue(data);
		call_rcu(&data->rcu, syscall_thread_group_free_rcu);
		ret = 0;
	}
	SYSCALL_TRACE("thread_group_remove(), status %i\n", ret);
	return ret;
}

static void syscall_thread_group_cleanup(void)
{
	struct syscall_thread *thread;
	struct syscall_thread_group *data, *data_next;

	list_for_each_entry_safe(data, data_next, &backend.thread_groups, list) {
		list_del_rcu(&data->list);
		syscall_prepare_terminate(data);
		/* We cannot hold a lock while stopping a thread, as it can request
		   this lock too. */
		while (1) {
			thread = list_first_entry_rcu(&data->threads, struct syscall_thread, list);
			if (&thread->list == &data->threads)
				break;
			kthread_syscall_stop(thread->task);
			call_rcu(&thread->rcu, syscall_thread_free_rcu);
		}
		syscall_thread_group_do_shrink_map(data, data->map_pos - SYSCALL_CALL_PAGES);
		syscall_unmap_rqueue(data);
		call_rcu(&data->rcu, syscall_thread_group_free_rcu);
	}
}

static void syscall_notify_main(syscall_backend_info_t *info, struct sccom_response *copy_rsp, size_t size)
{
	struct sccom_response *rsp;
	int notify;

	rsp = RING_GET_RESPONSE(&info->main_ring, info->main_ring.rsp_prod_pvt);
	memcpy(rsp, copy_rsp, size);
	info->main_ring.rsp_prod_pvt++;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&info->main_ring, notify);
	if (notify)
		notify_remote_via_irq(info->main_irq);
}

static size_t syscall_process_main(syscall_backend_info_t *info, struct sccom_request *req, struct sccom_response *rsp)
{
	size_t size;
	size_t i;

	switch (req->id) {
		case SYSCALL_ACTION_INIT:
			rsp->tgid = 0;
			rsp->num = SYSCALL_PREALLOC_PROCESSES;
			for (i = 0; i < SYSCALL_PREALLOC_PROCESSES; i++) {
				rsp->prealloc[i].id = i;
				memcpy(rsp->prealloc[i].gref, info->next_data[i]->map_gref,
					SYSCALL_CALL_PAGES * sizeof(uint32_t));
			}
			size = offsetof(struct sccom_response, grefs) + SYSCALL_PREALLOC_PROCESSES * sizeof(syscall_prealloc_t);
			break;

		case SYSCALL_ACTION_SHRINK_MAP:
			syscall_thread_group_shrink_map(req->tgid, req->mem.num);
			rsp->tgid = 0;
			rsp->num = 0;
			size = offsetof(struct sccom_response, grefs);
			break;

		case SYSCALL_ACTION_EXPAND_MAP:
			rsp->tgid = req->tgid;
			rsp->num = req->mem.num;
			if (syscall_thread_group_expand_map(req->tgid, rsp->grefs, req->mem.num)) {
				rsp->grefs[0] = -1; /* Error indicator */
				rsp->num = 1;
			}
			size = offsetof(struct sccom_response, grefs) + rsp->num * sizeof(uint32_t);
			break;

		case SYSCALL_ACTION_ADD:
			i = req->add.id;
			if (i >= SYSCALL_PREALLOC_PROCESSES)
				BUG();
			info->next_data[i]->page->entry[0].task_id = req->tgid;
			memcpy(info->next_data[i]->rqueue_gref, req->add.gref,
				SYSCALL_QUEUE_PAGES * sizeof(uint32_t));
			syscall_thread_group_add(info->next_data[i], req->tgid, req->add.ptgid, &req->add.cm);
			info->next_data[i] = syscall_thread_group_alloc();
			rsp->num = 1;
			rsp->tgid = 0;
			rsp->prealloc[0].id = i;
			memcpy(rsp->prealloc[0].gref, info->next_data[i]->map_gref,
				SYSCALL_CALL_PAGES * sizeof(uint32_t));
			size = offsetof(struct sccom_response, grefs) + sizeof(syscall_prealloc_t);
			break;

		case SYSCALL_ACTION_REMOVE:
			syscall_thread_group_remove(req->tgid);
			rsp->num = 0;
			rsp->tgid = req->tgid;
			size = offsetof(struct sccom_response, grefs);
			break;

		default:
			BUG();
			break;
	}
	wmb();
	return size;
}

static int syscall_main_thread(void *_info)
{
	syscall_backend_info_t *info = _info;
	RING_IDX rc, rp;
	int requests;

	while (1) {
		wait_event(info->main_queue, kthread_should_stop() ||
			info->main_avail != 0);

		info->main_avail = 0;
		smp_wmb();

		do {
			if (kthread_should_stop())
				goto done;

			rp = info->main_ring.sring->req_prod;
			rmb();
			rc = info->main_ring.req_cons;

			while (rc != rp) {
				struct sccom_request *req;
				struct sccom_response rsp;
				size_t size;

				if (RING_REQUEST_CONS_OVERFLOW(&info->main_ring, rc))
					break;

				req = RING_GET_REQUEST(&info->main_ring, rc);
				size = syscall_process_main(info, req, &rsp);
				info->main_ring.req_cons = ++rc;
				syscall_notify_main(info, &rsp, size);
				if (kthread_should_stop())
					goto done;
			}

			RING_FINAL_CHECK_FOR_REQUESTS(&info->main_ring, requests);
		} while (requests);
	}

done:
	return 0;
}

static void syscall_process_request(int id, uint32_t tgid, uint32_t pid)
{
	struct syscall_thread *thread;
	struct syscall_thread_group *data;
	struct task_struct *task;
	unsigned long flags;

	if (pid == 0)
		return;

	/* Find task  */
	rcu_read_lock();
	list_for_each_entry_rcu(data, &backend.thread_groups, list) {
		if (data->tgid == tgid)
			break;
	}
	if (&data->list != &backend.thread_groups) {
		if ((unsigned int) id < SYSCALL_REQUEST_FD) {
			thread = list_first_entry_rcu(&data->threads, struct syscall_thread, list);
			if (&thread->list != &data->threads) {
				task = thread->task; /* Get the first thread */
				write_efd_task(id, task);
			}
		} else if (id < 0) { /* SYSCALL_REQUEST_SIGNAL */
			spin_lock(&data->lock);
			list_for_each_entry_rcu(thread, &data->threads, list) { /* Find the thread */
				if (thread->task_id == pid) {
					if (SYSCALL_REQUEST_SIGNAL(thread->seq_num) == id) {
						task = thread->task;
						spin_lock_irqsave(&task->sighand->siglock, flags);
						signal_wake_up(task, 0);
						spin_unlock_irqrestore(&task->sighand->siglock, flags);
						break;
					}
				}
			}
			spin_unlock(&data->lock);
		}
	}
	rcu_read_unlock();
}

static int syscall_request_thread(void *_info)
{
	syscall_backend_info_t *info = _info;
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
				syscall_process_request(rsp->id, rsp->tgid, rsp->pid);
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

static irqreturn_t syscall_main_interrupt(int irq, void *dev_id)
{
	syscall_backend_info_t *info = dev_id;

	info->main_avail = 1;
	wake_up(&info->main_queue);
	return IRQ_HANDLED;
}

static irqreturn_t syscall_request_interrupt(int irq, void *dev_id)
{
	syscall_backend_info_t *info = dev_id;

	info->request_avail = 1;
	wake_up(&info->request_queue);
	return IRQ_HANDLED;
}

static irqreturn_t syscall_wake_interrupt(int irq, void *dev_id)
{
	if ((__sync_fetch_and_sub(&backend.wake_page->running_threads, SYSCALL_WAKE_IN_PROGRESS + SYSCALL_WAKE_REQUESTED) & 0x7FFFFFFFU) < MIN_RUNNING_THREADS) {
		if (!syscall_wake_groups(NULL)) { /* Did not wake up anybody */
			__sync_fetch_and_or(&backend.wake_page->running_threads, SYSCALL_WAKE_REQUESTED);
			syscall_wake_groups(NULL); /* Check one more time after setting the flag */
		}
	}
	return IRQ_HANDLED;
}

static irqreturn_t syscall_disconnect_interrupt(int irq, void *dev_id)
{
	syscall_backend_info_t *info = dev_id;

	smp_mb__before_atomic_inc();
	atomic_inc(&backend.disconnect_count);
	smp_mb__after_atomic_inc();
	wake_up(&info->disconnect_queue);
	return IRQ_HANDLED;
}

static int syscall_backend_register(syscall_backend_info_t *info)
{
	int err;

	memset(info->wake_page, 0, PAGE_SIZE);
	SHARED_RING_INIT(info->main_sring);
	BACK_RING_INIT(&info->main_ring, info->main_sring, PAGE_SIZE);
	SHARED_RING_INIT(info->front_sring);
	FRONT_RING_INIT(&info->front_ring, info->front_sring, PAGE_SIZE);
	SHARED_RING_INIT(info->back_sring);
	BACK_RING_INIT(&info->back_ring, info->back_sring, PAGE_SIZE);
	info->main_thread = kthread_create(syscall_main_thread, info,
		"syscall_main_thread");
	if (IS_ERR(info->main_thread)) {
		err = PTR_ERR(info->main_thread);
		goto error2;
	}
	info->request_thread = kthread_create(syscall_request_thread, info,
		"syscall_request_thread");
	if (IS_ERR(info->request_thread)) {
		err = PTR_ERR(info->request_thread);
		goto error1;
	}
	err = HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_REGISTER,
		SYSCALL_SYSID_CURRENT, &info->data);

	if (unlikely(err != 0))
		goto error0;

//	set_user_nice(info->main_thread, -19);
//	set_user_nice(info->request_thread, -19);
	wake_up_process(info->main_thread);
	wake_up_process(info->request_thread);

	return 0;

error0:
	kthread_stop(backend.request_thread);
error1:
	kthread_stop(backend.main_thread);
error2:
	return err;
}

static int syscall_backend_unregister(syscall_backend_info_t *info)
{
	int rc;

	rc = HYPERVISOR_syscall_service_op(SYSCALL_SERVICE_UNREGISTER, SYSCALL_SYSID_CURRENT, 0);
	if (rc == 0) {
		kthread_stop(info->request_thread);
		kthread_stop(info->main_thread);
		syscall_thread_group_cleanup();
		rcu_barrier();
		flush_workqueue(info->wq);
	}
	return rc;
}

static int syscall_disconnect_thread(void *_info)
{
	syscall_backend_info_t *info = _info;
	int rc, stop;

	while (1) {
		wait_event(info->disconnect_queue, (stop = kthread_should_stop()) ||
			atomic_read(&info->disconnect_count) != 0);
		if (stop)
			break;
		do {
			mutex_lock(&info->register_lock);
			rc = syscall_backend_unregister(&backend);
			BUG_ON(rc != 0);
			rc = syscall_backend_register(&backend);
			BUG_ON(rc != 0);
			info->exit_complete = 1;
			mutex_unlock(&info->register_lock);
			wake_up(&info->exit_queue);
		} while (!atomic_dec_and_test(&info->disconnect_count));
	}
	return 0;
}

static int __init syscall_backend_init(void)
{
	struct evtchn_alloc_unbound main_alloc, ring_alloc, disconnect_alloc, wake_alloc;
	struct evtchn_close close;
	size_t i;
	int err;

	backend.wq = create_singlethread_workqueue("syscall_wq");
	if (!backend.wq) {
		SYSCALL_ERROR("Cannot create a work queue\n");
		err = -ENOMEM;
		goto error15;
	}
	backend.thread_group_slab = kmem_cache_create("syscall_thread_group_slab", sizeof(struct syscall_thread_group), 0, 0, NULL);
	if (!backend.thread_group_slab) {
		SYSCALL_ERROR("Cannot create thread_group_slab\n");
		err = -ENOMEM;
		goto error14;
	}
	backend.thread_slab = kmem_cache_create("syscall_thread_slab", sizeof(struct syscall_thread), 0, 0, NULL);
	if (!backend.thread_slab) {
		SYSCALL_ERROR("Cannot create thread_slab\n");
		err = -ENOMEM;
		goto error13;
	}
	backend.main_irq = -1;
	backend.ring_irq = -1;
	backend.disconnect_irq = -1;
	backend.wake_irq = -1;
	INIT_LIST_HEAD(&backend.thread_groups);
	backend.wake_page = syscall_alloc_shared(&backend.wake_gref);
	if (unlikely(backend.wake_page == NULL)) {
		err = -ENOMEM;
		goto error12;
	}
	backend.main_sring = syscall_alloc_shared(&backend.main_gref);
	if (unlikely(backend.main_sring == NULL)) {
		err = -ENOMEM;
		goto error11;
	}
	backend.front_sring = syscall_alloc_shared(&backend.front_ring_gref);
	if (unlikely(backend.front_sring == NULL)) {
		err = -ENOMEM;
		goto error10;
	}
	backend.back_sring = syscall_alloc_shared(&backend.back_ring_gref);
	if (unlikely(backend.back_sring == NULL)) {
		err = -ENOMEM;
		goto error9;
	}
	for (i = 0; i < SYSCALL_PREALLOC_PROCESSES; i++) {
		backend.next_data[i] = syscall_thread_group_alloc();
		if (unlikely(backend.next_data[i] == NULL)) {
			err = -ENOMEM;
			goto error8;
		}
	}
	backend.request_avail = 0;
	backend.main_avail = 0;
	atomic_set(&backend.disconnect_count, 0);
	init_waitqueue_head(&backend.request_queue);
	init_waitqueue_head(&backend.main_queue);
	init_waitqueue_head(&backend.disconnect_queue);
	init_waitqueue_head(&backend.exit_queue);
	spin_lock_init(&backend.ring_lock);
	mutex_init(&backend.register_lock);
	smp_mb();

	main_alloc.dom = DOMID_SELF;
	main_alloc.remote_dom = DOM0;
	ring_alloc.dom = DOMID_SELF;
	ring_alloc.remote_dom = DOM0;
	disconnect_alloc.dom = DOMID_SELF;
	disconnect_alloc.remote_dom = DOM0;
	wake_alloc.dom = DOMID_SELF;
	wake_alloc.remote_dom = DOM0;

	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &main_alloc);
	if (unlikely(err != 0))
		goto error8;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &ring_alloc);
	if (unlikely(err != 0))
		goto error7;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &disconnect_alloc);
	if (unlikely(err != 0))
		goto error6;
	err = HYPERVISOR_event_channel_op(EVTCHNOP_alloc_unbound, &wake_alloc);
	if (unlikely(err != 0))
		goto error5;

	backend.data.wake_gref = backend.wake_gref;
	backend.data.main_gref = backend.main_gref;
	backend.data.back_ring_gref = backend.front_ring_gref;
	backend.data.front_ring_gref = backend.back_ring_gref;
	backend.data.main_port = main_alloc.port;
	backend.data.ring_port = ring_alloc.port;
	backend.data.disconnect_port = disconnect_alloc.port;
	backend.data.wake_port = wake_alloc.port;

	err = bind_evtchn_to_irqhandler(backend.data.main_port,
		syscall_main_interrupt, 0, "syscall_backend_irq_main", &backend);
	if (unlikely(err < 0))
		goto error4;
	backend.main_irq = err;
	smp_mb();
	err = bind_evtchn_to_irqhandler(backend.data.ring_port,
		syscall_request_interrupt, 0, "syscall_backend_irq_request", &backend);
	if (unlikely(err < 0))
		goto error3;
	backend.ring_irq = err;
	smp_mb();
	err = bind_evtchn_to_irqhandler(backend.data.disconnect_port,
		syscall_disconnect_interrupt, 0, "syscall_backend_irq_disconnect",
		&backend);
	if (unlikely(err < 0))
		goto error2;
	backend.disconnect_irq = err;
	smp_mb();
	err = bind_evtchn_to_irqhandler(backend.data.wake_port,
		syscall_wake_interrupt, 0, "syscall_backend_irq_wake", &backend);
	if (unlikely(err < 0))
		goto error1;
	backend.wake_irq = err;
	smp_mb();

	backend.disconnect_thread = kthread_create(syscall_disconnect_thread,
		&backend, "syscall_disconnect_thread");
	if (IS_ERR(backend.disconnect_thread)) {
		err = PTR_ERR(backend.disconnect_thread);
		goto error0;
	}

	err = syscall_backend_register(&backend);
	if (unlikely(err < 0)) {
		kthread_stop(backend.disconnect_thread);
		goto error0;
	}

	wake_up_process(backend.disconnect_thread);

	return 0;

error0:
	unbind_from_irqhandler(backend.wake_irq, &backend);
error1:
	unbind_from_irqhandler(backend.disconnect_irq, &backend);
error2:
	unbind_from_irqhandler(backend.ring_irq, &backend);
error3:
	unbind_from_irqhandler(backend.main_irq, &backend);
error4:
	if (backend.wake_irq == -1) {
		close.port = wake_alloc.port;
		if (HYPERVISOR_event_channel_op(EVTCHNOP_close, &close) != 0)
			BUG();
	}
error5:
	if (backend.disconnect_irq == -1) {
		close.port = disconnect_alloc.port;
		if (HYPERVISOR_event_channel_op(EVTCHNOP_close, &close) != 0)
			BUG();
	}
error6:
	if (backend.ring_irq == -1) {
		close.port = ring_alloc.port;
		if (HYPERVISOR_event_channel_op(EVTCHNOP_close, &close) != 0)
			BUG();
	}
error7:
	if (backend.main_irq == -1) {
		close.port = main_alloc.port;
		if (HYPERVISOR_event_channel_op(EVTCHNOP_close, &close) != 0)
			BUG();
	}
error8:
	while (i != 0) {
		syscall_unmap_rqueue(backend.next_data[--i]);
		syscall_thread_group_free(&backend.next_data[i]->rcu_work);
	}
	syscall_free_shared(backend.back_ring_gref, backend.back_sring);
error9:
	syscall_free_shared(backend.front_ring_gref, backend.front_sring);
error10:
	syscall_free_shared(backend.main_gref, backend.main_sring);
error11:
	syscall_free_shared(backend.wake_gref, backend.wake_page);
error12:
	kmem_cache_destroy(backend.thread_slab);
error13:
	kmem_cache_destroy(backend.thread_group_slab);
error14:
	destroy_workqueue(backend.wq);
error15:
	SYSCALL_ERROR("Fatal initialization error\n");
	return err;
}

static void __exit syscall_backend_exit(void)
{
	size_t i;
	int rc;

	while (1) {
		mutex_lock(&backend.register_lock);
		rc = syscall_backend_unregister(&backend);
		BUG_ON(rc < 0 && rc != -EAGAIN);
		backend.exit_complete = 0;
		mutex_unlock(&backend.register_lock);
		if (rc == 0)
			break;
		notify_remote_via_irq(backend.disconnect_irq);
		wait_event(backend.exit_queue, backend.exit_complete == 1);
	}

	/* Unbind all handlers */
	unbind_from_irqhandler(backend.ring_irq, &backend);
	unbind_from_irqhandler(backend.main_irq, &backend);
	unbind_from_irqhandler(backend.disconnect_irq, &backend);
	kthread_stop(backend.disconnect_thread);
	unbind_from_irqhandler(backend.wake_irq, &backend);
	/* Clean-up everything */
	syscall_free_shared(backend.front_ring_gref, backend.front_sring);
	syscall_free_shared(backend.back_ring_gref, backend.back_sring);
	syscall_free_shared(backend.main_gref, backend.main_sring);
	syscall_free_shared(backend.wake_gref, backend.wake_page);
	for (i = 0; i < SYSCALL_PREALLOC_PROCESSES; i++) {
		syscall_unmap_rqueue(backend.next_data[i]);
		syscall_thread_group_free(&backend.next_data[i]->rcu_work);
	}
	kmem_cache_destroy(backend.thread_slab);
	kmem_cache_destroy(backend.thread_group_slab);
	destroy_workqueue(backend.wq);
}

module_init(syscall_backend_init);
module_exit(syscall_backend_exit);

MODULE_LICENSE("Dual MIT/GPL");
