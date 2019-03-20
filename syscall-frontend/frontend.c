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

#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/syscall_service.h>
#include <linux/syscalls.h>
#include <xen/balloon.h>
#include <xen/events.h>
#include <asm/xen/page.h>

#define SYSCALL_MAP_FLAGS	(GNTMAP_host_map | GNTMAP_application_map \
				 | GNTMAP_contains_pte)
#define SYSCALL_KMAP_FLAGS	(GNTMAP_host_map | GNTMAP_contains_pte)

typedef struct syscall_frontend_manage {
	syscall_frontend_info_t *info;
	struct gnttab_map_grant_ref *map_ops;
} syscall_frontend_manage_t;

static syscall_irq_info_t syscall_irq[SYSCALL_SYSIDS];

static void syscall_frontend_notify_done(int sysid, int id, uint32_t tgid, uint32_t pid)
{
	syscall_irq_info_t *info = &syscall_irq[sysid];
	struct screq_response *rsp;
	int notify;

	if (syscall_service_enter(info))
		return;

again:
	spin_lock(&info->notify_lock);
	if (RING_FULL_RSP(&info->back_ring)) {
		spin_unlock(&info->notify_lock);
		yield();
		goto again;
	}

	rsp = RING_GET_RESPONSE(&info->back_ring, info->back_ring.rsp_prod_pvt);
	rsp->id = id;
	rsp->tgid = tgid;
	rsp->pid = pid;
	info->back_ring.rsp_prod_pvt++;
	RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(&info->back_ring, notify);
	if (notify)
		notify_remote_via_irq(info->ring_irq);
	spin_unlock(&info->notify_lock);

	syscall_service_leave(info);
}

static void syscall_unmap_pages(syscall_frontend_info_t *info, size_t start, size_t count)
{
	size_t num, i, s, total;
	int err;

	/* Unmap references */
	s = start;
	for (total = count; total != 0; total -= num) {
		/* Find out the beginning of the map */
		while (1) {
			if (info->unmap_ops[s].handle != -1)
				break;
			s++;
			if (--total == 0)
				return;
		}
		/* Find number of pages */
		num = 1;
		while (num < total) {
			if (info->unmap_ops[s + num].handle == -1)
				break;
			num++;
		}
		/* Unmap */
#if 0 /* For newer Linux versions */
		err = gnttab_unmap_refs(info->unmap_ops + s, info->pages + s, num, true);
#else
		err = gnttab_unmap_refs(info->unmap_ops + s, info->pages + s, num);
#endif
		WARN_ON(err);
		for (i = s; i < s + num; i++) {
			WARN_ON(info->unmap_ops[i].status != GNTST_okay);
			info->unmap_ops[i].handle = -1;
		}
		s += num;
	}
}

static void syscall_frontend_mn_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	syscall_frontend_info_t *info = container_of(mn, syscall_frontend_info_t, mn);

	spin_lock(&info->lock);
	if (info->vma) {
		syscall_unmap_pages(info, 0, info->map_pos);
		info->vma = NULL;
		info->mmu_registered = 0;
	}
	spin_unlock(&info->lock);
}

static void syscall_frontend_mn_invl_range_start(struct mmu_notifier *mn, struct mm_struct *mm, unsigned long start, unsigned long end)
{
	syscall_frontend_info_t *info;
	size_t i, n;
	unsigned long addr;

	info = container_of(mn, syscall_frontend_info_t, mn);
	spin_lock(&info->lock);
	if (info->vma && info->vma->vm_start < end
	    && info->vma->vm_end > start) {
		addr = max(start, info->vma->vm_start);
		i = (addr - info->vma->vm_start) >> PAGE_SHIFT;
		addr = min(end, info->vma->vm_end);
		n = (addr - info->vma->vm_start) >> PAGE_SHIFT;
		if (n > info->map_pos)
			n = info->map_pos;
		syscall_unmap_pages(info, i, n - i);
	}
	spin_unlock(&info->lock);
}

static void syscall_frontend_mn_invl_page(struct mmu_notifier *mn, struct mm_struct *mm, unsigned long addr)
{
	syscall_frontend_mn_invl_range_start(mn, mm, addr, addr + PAGE_SIZE);
}

static struct mmu_notifier_ops syscall_frontend_mmu_ops = {
	.release		= syscall_frontend_mn_release,
	.invalidate_page	= syscall_frontend_mn_invl_page,
	.invalidate_range_start	= syscall_frontend_mn_invl_range_start
};

static int syscall_frontend_open(struct inode *inode, struct file *filep, uint32_t sysid)
{
	syscall_frontend_private_t *priv;
	syscall_add_t data;
	size_t i;
	int err;

	priv = (syscall_frontend_private_t *) kmalloc(sizeof(syscall_frontend_private_t), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->service = &syscall_irq[sysid];
	mutex_init(&priv->lock);
	spin_lock_init(&priv->info.lock);
	if (alloc_xenballooned_pages(SYSCALL_PAGES, priv->info.pages, false)) {
		err = -ENOMEM;
		goto error2;
	}
	priv->info.wake_page = pfn_to_kaddr(page_to_pfn(priv->info.pages[0]));
	priv->info.map_pos = SYSCALL_PAGES;
	priv->info.vma = NULL;
	priv->info.mmu_registered = 0;
	priv->tgid = current->tgid;
	if (syscall_service_add(priv->service, current, &data)) {
		SYSCALL_ERROR("Cannot register task %u\n", priv->tgid);
		err = -EFAULT;
		goto error1;
	}
	for (i = 0; i < SYSCALL_PAGES; i++) {
		priv->info.grefs[i] = data.gref[i];
		priv->info.unmap_ops[i].handle = -1; /* No actual mapping yet */
	}
	priv->info.domid = data.domid;
	filep->private_data = priv;
	return 0;

error1:
	free_xenballooned_pages(SYSCALL_PAGES, priv->info.pages);
error2:
	kfree(priv);
	return err;
}

static int syscall_network_open(struct inode *inode, struct file *filep)
{
	return syscall_frontend_open(inode, filep, SYSCALL_SYSID_NETWORK);
}

static int syscall_storage_open(struct inode *inode, struct file *filep)
{
	return syscall_frontend_open(inode, filep, SYSCALL_SYSID_STORAGE);
}

static int manage_grant_ptes(pte_t *pte, pgtable_t token, unsigned long addr, void *_data)
{
	syscall_frontend_manage_t *data = (syscall_frontend_manage_t *) _data;
	syscall_frontend_info_t *info = data->info;
	size_t index = (addr - info->vma->vm_start) >> PAGE_SHIFT;
	uint32_t flags = SYSCALL_MAP_FLAGS;
	uint64_t maddr;

	/* Set write protection for the wake page */
	if (index == 0)
		flags |= GNTMAP_readonly;

	maddr = arbitrary_virt_to_machine(pte).maddr;
	gnttab_set_map_op(data->map_ops + index, maddr, flags, info->grefs[index], info->domid); 
	gnttab_set_unmap_op(info->unmap_ops + index, maddr, flags, -1);
	return 0;
}

static int syscall_map_pages(syscall_frontend_info_t *info, unsigned long start, unsigned long count)
{
	syscall_frontend_manage_t manage_data;
	struct gnttab_map_grant_ref *map_ops;
	pte_t *ptep;
	unsigned long addr;
	unsigned level;
	uint64_t maddr;
	size_t i;
	int err;

	map_ops = (struct gnttab_map_grant_ref *) kmalloc(count * sizeof(struct gnttab_map_grant_ref), GFP_KERNEL);
	if (!map_ops)
		return -ENOMEM;

	addr = info->vma->vm_start + (start << PAGE_SHIFT);
	manage_data.info = info;
	manage_data.map_ops = map_ops - start; /* To offset properly index */
	err = apply_to_page_range(info->vma->vm_mm, addr, (count << PAGE_SHIFT), manage_grant_ptes, &manage_data);
	if (err) {
		SYSCALL_ERROR("manage_grant_ptes() error\n");
		goto done;
	}

	for (i = start; i < start + count; i++) {
		addr = (unsigned long) pfn_to_kaddr(page_to_pfn(info->pages[i]));
		ptep = lookup_address(addr, &level);
		maddr = arbitrary_virt_to_machine(ptep).maddr;
		gnttab_set_map_op(info->kmap_ops + i, maddr, SYSCALL_KMAP_FLAGS,
				  info->grefs[i], info->domid);
	}

	err = gnttab_map_refs(map_ops, info->kmap_ops + start, info->pages + start, count);
	if (err)
		goto done;

	for (i = 0; i < count; i++) {
		if (map_ops[i].status == GNTST_okay) {
			BUG_ON(map_ops[i].handle == -1);
			info->unmap_ops[i + start].handle = map_ops[i].handle;
		} else {
			err = -EFAULT;
		}
	}

	/* Unmap pages if an error occurs */
	if (err)
		syscall_unmap_pages(info, start, count);

done:
	kfree(map_ops);
	return err;
}

static int syscall_frontend_mmap(struct file *filep, struct vm_area_struct *vma)
{
	syscall_frontend_private_t *priv = (syscall_frontend_private_t *) filep->private_data;
	syscall_frontend_info_t *info;
	uint32_t map_pos;
	int err;

	if (vma->vm_end - vma->vm_start != PAGE_SIZE * SYSCALL_TOTAL_SHARED_PAGES
		|| !(vma->vm_flags & VM_SHARED) || !(vma->vm_flags & VM_WRITE))
		return -EINVAL;

	mutex_lock(&priv->lock);
	info = &priv->info;
	spin_lock(&info->lock);
	/* Check that MMU notifier is registered, and we do not mmap() twice */
	if (!info->mmu_registered || info->vma != NULL) {
		err = -EFAULT;
		goto error;
	}
	vma->vm_flags |= VM_RESERVED | VM_DONTEXPAND | VM_DONTCOPY | VM_PFNMAP;
	info->vma = vma;
	map_pos = info->map_pos;
	spin_unlock(&info->lock);
	err = syscall_map_pages(info, 0, map_pos);
	if (err) {
		spin_lock(&info->lock);
		info->vma = NULL;
error:
		spin_unlock(&info->lock);
	}
	mutex_unlock(&priv->lock);
	return err;
}

static int syscall_frontend_release(struct inode *inode, struct file *filep)
{
	char path[sizeof(SYSCALL_FDTABLE_PATH) + 32];
	syscall_frontend_private_t *priv = (syscall_frontend_private_t *) filep->private_data;
	int err;

	if (priv) {
		if (priv->info.mmu_registered)
			mmu_notifier_unregister(&priv->info.mn, priv->mm);
		syscall_unmap_pages(&priv->info, 0, priv->info.map_pos);
		free_xenballooned_pages(priv->info.map_pos, priv->info.pages);
		err = syscall_service_remove(priv->service, priv->tgid);
		if (err) {
			SYSCALL_WARNING("Possible remote domain crash or disconnection?\n");
		}
		sprintf(path, SYSCALL_FDTABLE_PATH "%u", current->tgid);
		sys_unlink(path);
		kfree(priv);
	}
	return 0;
}

static long syscall_frontend_wake(struct file *filep)
{
	syscall_frontend_private_t *priv = (syscall_frontend_private_t *) filep->private_data;
	syscall_wake_page_t *wake_page = priv->info.wake_page;
	syscall_irq_info_t *service = priv->service;
	uint64_t running_threads;

	do {
		running_threads = wake_page->running_threads;
		if ((running_threads & (SYSCALL_WAKE_REQUESTED | SYSCALL_WAKE_IN_PROGRESS)) != SYSCALL_WAKE_REQUESTED)
			return 0;
	} while (!__sync_bool_compare_and_swap(&wake_page->running_threads, running_threads, running_threads + SYSCALL_WAKE_IN_PROGRESS));

	if (syscall_service_enter(service))
		return 0;
	notify_remote_via_irq(service->wake_irq);
	syscall_service_leave(service);
	return 0;
}

static long syscall_frontend_expand_buffer(struct file *filep, uint32_t num)
{
	syscall_frontend_private_t *priv = (syscall_frontend_private_t *) filep->private_data;
	syscall_frontend_info_t *info;
	syscall_irq_info_t *service = priv->service;
	size_t total, count;
	int rc;
	long err;

	mutex_lock(&priv->lock);
	info = &priv->info;
	if (info->vma == NULL) {
		err = -EFAULT;
		goto error;
	}
	if (num > SYSCALL_TOTAL_SHARED_PAGES - info->map_pos) {
		err = -EINVAL;
		goto error;
	}
	total = num;
	for (; num != 0; num -= count) {
		count = SYSCALL_MAX_EXPAND_MAP_GREFS;
		if (count > num)
			count = num;
		rc = syscall_service_expand_map(service, priv->tgid,
			info->grefs + info->map_pos, count);
		if (rc) {
			SYSCALL_ERROR("Cannot expand a shared buffer\n");
			goto done;
		}
		if (alloc_xenballooned_pages(count, info->pages + info->map_pos, false)) {
			goto error_map;
		}
		rc = syscall_map_pages(info, info->map_pos, count);
		if (rc) {
			free_xenballooned_pages(count, info->pages + info->map_pos);
error_map:
			rc = syscall_service_shrink_map(service, priv->tgid, count);
			if (rc) {
				SYSCALL_WARNING("Possible remote domain crash or disconnection?\n");
			}
			goto done;
		}
		spin_lock(&info->lock);
		info->map_pos += count;
		spin_unlock(&info->lock);
	}

done:
	err = total - num;
error:
	mutex_unlock(&priv->lock);
	return err;
}

static long syscall_frontend_shrink_buffer(struct file *filep, unsigned long num)
{
	syscall_frontend_private_t *priv = (syscall_frontend_private_t *) filep->private_data;
	syscall_frontend_info_t *info;
	long err = 0;
	int rc;

	mutex_lock(&priv->lock);
	info = &priv->info;
	if (info->vma == NULL) {
		err = -EFAULT;
		goto error;
	}
	if (num > info->map_pos - SYSCALL_PAGES) {
		err = -EINVAL;
		goto error;
	}
	syscall_unmap_pages(info, info->map_pos - num, num);
	free_xenballooned_pages(num, info->pages + info->map_pos - num);
	spin_lock(&info->lock);
	info->map_pos -= num;
	spin_unlock(&info->lock);

	rc = syscall_service_shrink_map(priv->service, priv->tgid, num);
	if (rc) {
		SYSCALL_WARNING("Possible remote domain crash or disconnection?\n");
	}

error:
	mutex_unlock(&priv->lock);
	return err;
}

static long syscall_frontend_register(struct file *filep)
{
	syscall_frontend_private_t *priv = (syscall_frontend_private_t *) filep->private_data;
	syscall_frontend_info_t *info;
	long ret;

	mutex_lock(&priv->lock);
	info = &priv->info;
	spin_lock(&info->lock);
	if (info->mmu_registered) {
		ret = -EFAULT;
		goto error2;
	}
	priv->mm = get_task_mm(current);
	if (!priv->mm) {
		ret = -ENOMEM;
		goto error1;
	}
	info->mn.ops = &syscall_frontend_mmu_ops;
	ret = mmu_notifier_register(&info->mn, priv->mm);

error1:
	mmput(priv->mm);
	if (ret)
		goto error2;
	info->mmu_registered = 1;
	ret = info->map_pos;

error2:
	spin_unlock(&info->lock);
	mutex_unlock(&priv->lock);

	return ret;
}

static long syscall_frontend_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		case SYSCALL_DRIVER_IOCTL_REGISTER:
			return syscall_frontend_register(filep);
		case SYSCALL_DRIVER_IOCTL_EXPAND_BUFFER:
			return syscall_frontend_expand_buffer(filep, arg);
		case SYSCALL_DRIVER_IOCTL_SHRINK_BUFFER:
			return syscall_frontend_shrink_buffer(filep, arg);
		case SYSCALL_DRIVER_IOCTL_WAKE:
			return syscall_frontend_wake(filep);
	}
	return -EINVAL;
}

static int syscall_service_open(struct inode *inode, struct file *filep)
{
	return 0;
}

static int syscall_service_mmap(struct file *filep, struct vm_area_struct *vma)
{
	if (vma->vm_end - vma->vm_start != PAGE_SIZE * SYSCALL_QUEUE_PAGES
		|| !(vma->vm_flags & VM_SHARED) || !(vma->vm_flags & VM_WRITE))
		return -EINVAL;

	return remap_pfn_range(vma, vma->vm_start,
			page_to_pfn(current->rqueue_page),
			PAGE_SIZE * SYSCALL_QUEUE_PAGES, vma->vm_page_prot);
}

static int syscall_service_release(struct inode *inode, struct file *filep)
{
	return 0;
}

static long syscall_service_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	int rc;

	if (arg >= SYSCALL_SYSIDS)
		return -EINVAL;

	mutex_lock(&syscall_irq[arg].service_lock);
	switch (cmd) {
		case SYSCALL_SERVICE_IOCTL_CONNECT:
			rc = syscall_service_connect(&syscall_irq[arg], arg);
			break;
		case SYSCALL_SERVICE_IOCTL_DISCONNECT:
			rc = syscall_service_disconnect(&syscall_irq[arg]);
			break;
		case SYSCALL_SERVICE_IOCTL_CLEANUP:
			rc = syscall_service_cleanup(&syscall_irq[arg]);
			break;
		default:
			rc = -EINVAL;
			break;
	}
	mutex_unlock(&syscall_irq[arg].service_lock);
	return rc;
}

static struct file_operations syscall_network_ops = {
	.owner = THIS_MODULE,
	.open = syscall_network_open,
	.mmap = syscall_frontend_mmap,
	.release = syscall_frontend_release,
	.unlocked_ioctl = syscall_frontend_ioctl
};

static struct file_operations syscall_storage_ops = {
	.owner = THIS_MODULE,
	.open = syscall_storage_open,
	.mmap = syscall_frontend_mmap,
	.release = syscall_frontend_release,
	.unlocked_ioctl = syscall_frontend_ioctl
};

static struct miscdevice syscall_network_device = {
	.minor = 240,
	.name = "syscall_network",
	.fops = &syscall_network_ops,
	.mode = 0666
};

static struct miscdevice syscall_storage_device = {
	.minor = 241,
	.name = "syscall_storage",
	.fops = &syscall_storage_ops,
	.mode = 0666
};

static struct file_operations syscall_service_ops = {
	.owner = THIS_MODULE,
	.open = syscall_service_open,
	.mmap = syscall_service_mmap,
	.release = syscall_service_release,
	.unlocked_ioctl = syscall_service_ioctl
};

static struct miscdevice syscall_service_device = {
	.minor = 242,
	.name = "syscall_service",
	.fops = &syscall_service_ops
};

static int __init syscall_frontend_init(void)
{
	int err;

	if (!xen_pv_domain())
		return -ENODEV;
	err = misc_register(&syscall_network_device);
	if (unlikely(err != 0)) {
		SYSCALL_ERROR("Cannot register /dev/syscall_network\n");
		goto error4;
	}
	err = misc_register(&syscall_storage_device);
	if (unlikely(err != 0)) {
		SYSCALL_ERROR("Cannot register /dev/syscall_storage\n");
		goto error3;
	}
	err = misc_register(&syscall_service_device);
	if (unlikely(err != 0)) {
		SYSCALL_ERROR("Cannot register /dev/syscall_service\n");
		goto error2;
	}
#if 0
	write_cr0(read_cr0() & ~X86_CR0_WP);
	if (read_cr0() & X86_CR0_WP) {
		SYSCALL_ERROR("Cannot disable write protection\n");
		goto error1;
	}
#endif
	syscall_service_init(&syscall_irq[SYSCALL_SYSID_NETWORK]);
	syscall_service_init(&syscall_irq[SYSCALL_SYSID_STORAGE]);
	err = syscall_service_start();
	if (unlikely(err != 0)) {
		SYSCALL_ERROR("Cannot initialize syscall service\n");
		goto error1;
	}
	syscall_notify = syscall_frontend_notify_done;
	//syscall_wake = syscall_frontend_wake;
	return 0;

error1:
	misc_deregister(&syscall_service_device);
error2:
	misc_deregister(&syscall_storage_device);
error3:
	misc_deregister(&syscall_network_device);
error4:
	return err;
}

static void __exit syscall_frontend_exit(void)
{
	syscall_service_disconnect(&syscall_irq[SYSCALL_SYSID_STORAGE]);
	syscall_service_disconnect(&syscall_irq[SYSCALL_SYSID_NETWORK]);
	syscall_notify = syscall_notify_stub;
	//syscall_wake = syscall_wake_stub;
	syscall_service_exit();
	misc_deregister(&syscall_service_device);
	misc_deregister(&syscall_storage_device);
	misc_deregister(&syscall_network_device);
}

MODULE_LICENSE("Dual MIT/GPL");

module_init(syscall_frontend_init);
module_exit(syscall_frontend_exit);
