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

#ifndef _SYSCALL_BACKEND_H
#define _SYSCALL_BACKEND_H	1

#include <linux/module.h>
#include <linux/init.h>
#include <linux/atomic.h>
#include <linux/semaphore.h>
#include <linux/kthread.h>
#include <linux/signal.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <xen/grant_table.h>
#include <xen/interface/io/ring.h>

#include "_syscall.h"
#include "_syscall_defs.h"
#include "_syscall_stack.h"
#include "_syscall_queue.h"
#include "_syscall_num.h"

#define SYSCALL_QUEUE_STOP			1UL
#define SYSCALL_QUEUE_STEP			2UL
#define SYSCALL_YIELD_COUNT			5000
//#define SYSCALL_YIELD_COUNT			500000000
//#define SYSCALL_YIELD_COUNT			500
#define MIN_RUNNING_THREADS			(num_online_cpus())
//#define MIN_RUNNING_THREADS			(num_online_cpus()+1)

struct syscall_thread_group;

struct syscall_thread {
	struct list_head		list;
	struct syscall_thread_group	*data;
	struct task_struct		*task;
	uint32_t				task_id;
	uint32_t				seq_num;
	struct rcu_head			rcu;
	struct work_struct		rcu_work;
};

struct syscall_thread_group {
	syscall_ptr_t		fetch_top;
	struct list_head		list;
	struct list_head		threads;
	unsigned long			num_queue;
	unsigned long			num_wakes;
	wait_queue_head_t		queue;
	struct spinlock			lock;
	syscall_page_t			*page;
	uint32_t				yield_count;
	uint32_t				tgid;
	uint32_t				map_pos;
	struct vm_struct		*map_area;
	struct page				*map_pages[SYSCALL_TOTAL_SHARED_PAGES];
	grant_ref_t				map_gref[SYSCALL_TOTAL_SHARED_PAGES];
	struct vm_struct		*rqueue_area;
	struct syscall_queue	*rqueue;
	struct page				*rqueue_pages[SYSCALL_QUEUE_PAGES];
	grant_ref_t				rqueue_gref[SYSCALL_QUEUE_PAGES];
	struct gnttab_unmap_grant_ref	rqueue_unmap[SYSCALL_QUEUE_PAGES];
	int						init_efd;
	atomic_t				idle_counter;
	struct rcu_head			rcu;
	struct work_struct		rcu_work;
	char					name[64];
};

typedef struct syscall_backend_info {
	struct list_head		thread_groups;
	struct sccom_back_ring	main_ring;
	struct screq_front_ring	front_ring;
	struct screq_back_ring	back_ring;
	syscall_wake_page_t		*wake_page;
	struct sccom_sring		*main_sring;
	struct screq_sring		*front_sring;
	struct screq_sring		*back_sring;
	struct kmem_cache		*thread_group_slab;
	struct kmem_cache		*thread_slab;
	struct workqueue_struct	*wq;
	struct task_struct		*main_thread;
	struct task_struct		*request_thread;
	struct task_struct		*disconnect_thread;
	struct syscall_thread_group	*next_data[SYSCALL_PREALLOC_PROCESSES];
	atomic_t				disconnect_count;
	uint32_t				main_gref;
	uint32_t				front_ring_gref;
	uint32_t				back_ring_gref;
	uint32_t				wake_gref;
	int						main_irq;
	int						ring_irq;
	int						disconnect_irq;
	int						wake_irq;
	int						exit_complete;
	int						main_avail;
	int						request_avail;
	wait_queue_head_t		exit_queue;
	wait_queue_head_t		disconnect_queue;
	wait_queue_head_t		main_queue;
	wait_queue_head_t		request_queue;
	struct spinlock			ring_lock;
	struct mutex			register_lock;
	syscall_connect_t		data;
} syscall_backend_info_t;

#define DOM0					0
#define SYSCALL_MAX_SHARED_SIZE	SYSCALL_MAX_SHARED_PAGES * PAGE_SIZE

void syscall_sync_cred(struct syscall_thread_group *data, const struct cred *cred);
void syscall_backend_notify_done(int id, uint32_t tgid, uint32_t pid);

#endif /* !_SYSCALL_BACKEND_H */
