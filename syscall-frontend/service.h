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

#ifndef _SYSCALL_FRONTEND_SERVICE_H
#define _SYSCALL_FRONTEND_SERVICE_H	1

#include "frontend.h"

#include <linux/wait.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/list.h>

struct syscall_expand_list {
	struct list_head	list;
	uint32_t	tgid;
	uint32_t	num;
	uint32_t	grefs[SYSCALL_MAX_EXPAND_MAP_GREFS];
};

struct syscall_remove_list {
	struct list_head	list;
	uint32_t	tgid;
};

typedef struct syscall_irq_info {
	syscall_prealloc_process_t processes;
	struct sccom_front_ring main_ring;
	struct screq_front_ring front_ring;
	struct screq_back_ring back_ring;
	struct vm_struct *main_area;
	struct vm_struct *front_ring_area;
	struct vm_struct *back_ring_area;
	unsigned long counter;
	size_t remove_version;
	struct list_head remove_list;
	size_t expand_version;
	struct list_head expand_list;
	grant_handle_t main_handle;
	grant_handle_t front_ring_handle;
	grant_handle_t back_ring_handle;
	uint32_t wake_gref;
	int main_irq;
	int ring_irq;
	int disconnect_irq;
	int wake_irq;
	uint32_t domid;
	int sysid;
	int request_avail;
	int connected;
	wait_queue_head_t add_queue;
	wait_queue_head_t expand_queue;
	wait_queue_head_t remove_queue;
	wait_queue_head_t request_queue;
	struct semaphore disconnect_sem;
	struct spinlock expand_lock;
	struct spinlock remove_lock;
	struct spinlock main_lock;
	struct spinlock notify_lock;
	struct mutex service_lock;
	struct task_struct *request_thread;
	struct task_struct *terminate_thread;
} syscall_irq_info_t;

typedef struct syscall_add_t {
	uint32_t	domid;
	uint32_t	gref[SYSCALL_PAGES];
} syscall_add_t;

void syscall_service_do_terminate(syscall_irq_info_t *info);

static inline int syscall_service_enter(syscall_irq_info_t *info)
{
	unsigned long val;

	do {
		val = info->counter;
		if (val < SYSCALL_STATE_RUNNING)
			return 1;
	} while (!__sync_bool_compare_and_swap(&info->counter, val, val + 1));

	return 0;
}

static inline void syscall_service_leave(syscall_irq_info_t *info)
{
	if (__sync_sub_and_fetch(&info->counter, 1) == SYSCALL_STATE_TERMINATED)
		wake_up_process(info->terminate_thread);
}

static inline void syscall_service_init(syscall_irq_info_t *info)
{
	mutex_init(&info->service_lock);
	info->main_lock = __SPIN_LOCK_UNLOCKED(info->main_lock);
	info->expand_lock = __SPIN_LOCK_UNLOCKED(info->expand_lock);
	info->remove_lock = __SPIN_LOCK_UNLOCKED(info->remove_lock);
	info->notify_lock = __SPIN_LOCK_UNLOCKED(info->notify_lock);
	info->counter = SYSCALL_STATE_TERMINATED;
	smp_mb();
}

int syscall_service_start(void);
void syscall_service_exit(void);
int syscall_service_cleanup(syscall_irq_info_t *info);
int syscall_service_connect(syscall_irq_info_t *info, uint32_t sysid);
int syscall_service_disconnect(syscall_irq_info_t *info);
int syscall_service_add(syscall_irq_info_t *info, struct task_struct *task,
	syscall_add_t *data);
int syscall_service_remove(syscall_irq_info_t *info, uint32_t tgid);
int syscall_service_shrink_map(syscall_irq_info_t *info, uint32_t tgid,
	uint32_t num);
int syscall_service_expand_map(syscall_irq_info_t *info, uint32_t tgid,
	uint32_t *ptr, uint32_t num);

#endif /* !_SYSCALL_FRONTEND_SERVICE_H */
