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

#ifndef _SYSCALL_COMMON_SYSCALL_H
#define _SYSCALL_COMMON_SYSCALL_H 1

#include "_syscall_defs.h"

/* Hypercall parameters */
#define SYSCALL_SERVICE_PREPARE			0
#define SYSCALL_SERVICE_CANCEL			1
#define SYSCALL_SERVICE_CONNECT			2
#define SYSCALL_SERVICE_DISCONNECT		3
#define SYSCALL_SERVICE_CLEANUP			4
#define SYSCALL_SERVICE_REGISTER		5
#define SYSCALL_SERVICE_UNREGISTER		6

/* Syscall service states */
#define SYSCALL_STATE_TERMINATED		0
#define SYSCALL_STATE_RUNNING			(unsigned long) (LONG_MIN)

/* Main ring buffer requests */
#define SYSCALL_ACTION_INIT				0
#define SYSCALL_ACTION_ADD				1
#define SYSCALL_ACTION_REMOVE			2
#define SYSCALL_ACTION_EXPAND_MAP		3
#define SYSCALL_ACTION_SHRINK_MAP		4

#define SYSCALL_PREALLOC_PROCESSES		8

#define SYSCALL_SYSID_NETWORK			0
#define SYSCALL_SYSID_STORAGE			1
#define SYSCALL_SYSIDS					2

#define SYSCALL_QUEUE_ORDER				3
#define SYSCALL_QUEUE_PAGES				(1U << SYSCALL_QUEUE_ORDER)
#define SYSCALL_CALL_PAGES				8
#define SYSCALL_PAGES					(SYSCALL_CALL_PAGES + 1)
#define SYSCALL_DATA_SHARED_PAGES		8192
#define SYSCALL_TOTAL_SHARED_PAGES		(SYSCALL_PAGES + SYSCALL_DATA_SHARED_PAGES)
#define SYSCALL_MAX_EXPAND_MAP_GREFS		80
#define SYSCALL_MAX_GROUPS					16
#define SYSCALL_FDTABLE_PATH				"/tmp/sclib_"

#define SYSCALL_IOCTL_MAGIC					0x81
#define SYSCALL_DRIVER_IOCTL_REGISTER		_IO(SYSCALL_IOCTL_MAGIC, 0)
#define SYSCALL_DRIVER_IOCTL_EXPAND_BUFFER	_IO(SYSCALL_IOCTL_MAGIC, 1)
#define SYSCALL_DRIVER_IOCTL_SHRINK_BUFFER	_IO(SYSCALL_IOCTL_MAGIC, 2)
#define SYSCALL_DRIVER_IOCTL_WAKE			_IO(SYSCALL_IOCTL_MAGIC, 3)
#define SYSCALL_SERVICE_IOCTL_CONNECT		_IO(SYSCALL_IOCTL_MAGIC, 8)
#define SYSCALL_SERVICE_IOCTL_DISCONNECT	_IO(SYSCALL_IOCTL_MAGIC, 9)
#define SYSCALL_SERVICE_IOCTL_CLEANUP		_IO(SYSCALL_IOCTL_MAGIC, 10)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct syscall_connect {
	uint32_t	domid;
	uint32_t	main_port;
	uint32_t	ring_port;
	uint32_t	disconnect_port;
	uint32_t	wake_port;
	uint32_t	main_gref;
	uint32_t	front_ring_gref;
	uint32_t	back_ring_gref;
	uint32_t	wake_gref;
} syscall_connect_t;

//#define SYSCALL_DEBUG

#ifdef __KERNEL__

#include <xen/interface/io/ring.h>

typedef struct syscall_prealloc {
	uint32_t	id;
	uint32_t	gref[SYSCALL_CALL_PAGES];
} syscall_prealloc_t;

typedef struct syscall_prealloc_process {
	syscall_ptr_t alloc_top;
	syscall_ptr_t free_top;
	size_t next[SYSCALL_PREALLOC_PROCESSES];
	syscall_prealloc_t entry[SYSCALL_PREALLOC_PROCESSES];
} syscall_prealloc_process_t;

struct sccom_request_add {
	uint32_t	id;
	uint32_t	ptgid;
	uint32_t	gref[SYSCALL_QUEUE_PAGES];
	struct cred_move	cm;
	gid_t	_pad[SYSCALL_MAX_GROUPS];	/* Groups for credentials */
};

struct sccom_request_memory {
	uint32_t	num;
};

struct sccom_response {
	uint32_t	tgid;
	uint32_t	num;
	union {
		syscall_prealloc_t	prealloc[SYSCALL_PREALLOC_PROCESSES];
		uint32_t			grefs[SYSCALL_MAX_EXPAND_MAP_GREFS];
	};
};

struct sccom_request {
	int			id;
	uint32_t	tgid;
	union {
		struct sccom_request_add	add;
		struct sccom_request_memory	mem;
	};
};

struct screq_response {
	int			id;
	uint32_t	tgid;
	uint32_t	pid;
};

struct screq_request {
	char		pad[0]; /* Just a stub */
};

#define RING_FULL_RSP(_r)	\
	(RING_SIZE(_r) - ((_r)->rsp_prod_pvt - (_r)->sring->rsp_event) == 1)

DEFINE_RING_TYPES(sccom, struct sccom_request, struct sccom_response);
DEFINE_RING_TYPES(screq, struct screq_request, struct screq_response);

#ifdef SYSCALL_DEBUG
# define SYSCALL_TRACE(fmt, ...)	printk(KERN_INFO "[SC-CALL:%u:%u] " fmt, current->tgid, current->pid, ##__VA_ARGS__)
#else
# define SYSCALL_TRACE(fmt, ...)
#endif

#define SYSCALL_WARNING(fmt, ...)		printk(KERN_WARNING "[SC-WARNING:%u:%u] " fmt, current->tgid, current->pid, ##__VA_ARGS__)

#define SYSCALL_ERROR(fmt, ...)		printk(KERN_ERR "[SC-ERROR:%u:%u] " fmt, current->tgid, current->pid, ##__VA_ARGS__)

#endif /* __KERNEL__ */

#define SYSCALL_REQUEST_FD			0x7FFFFFFF
#define SYSCALL_REQUEST_NOTIFY		0x7FFFFFFF
#define SYSCALL_REQUEST_SIGNAL(x)	((x) | 0x80000000)

#define SYSCALL_ENTRY_RQUEUE		0x80U
#define SYSCALL_ENTRY_DONE			0xFFU

/* Double word definition */
#if defined(__x86_64__)
typedef __int128_t syscall_sdw_t;
typedef __uint128_t syscall_udw_t;
# define SYSCALL_INT_PTR(x)				((int *) (x))	/* Little Endian */
#elif defined(__i386__)
typedef int64_t syscall_sdw_t;
typedef uint64_t syscall_udw_t;
# define SYSCALL_INT_PTR(x)				((int *) (x))	/* Little Endian */
#endif

#define syscall_entry_result_lower(x)	((x)->args[0])
#define syscall_entry_result_upper(x)	((x)->args[1])

#define syscall_entry_result_sw(x)		((x)->args[0])
#define syscall_entry_result_dw(x)	\
	(((syscall_udw_t) (x)->args[1] << (sizeof(long) * 8)) | (x)->args[0])

#define syscall_result_lower(x)			((unsigned long) (x))
#define syscall_result_upper(x)			((unsigned long) ((syscall_udw_t) (x) >> (sizeof(long) * 8)))

struct pthread;

typedef struct syscall_entry {
	unsigned char id;
	unsigned char signal;
	unsigned short seq_num;
	unsigned int task_id;
	struct pthread *pd;
	unsigned long args[6];
} syscall_entry_t;

#define SYSCALL_MAX_PTHREADS	((SYSCALL_QUEUE_PAGES * PAGE_SIZE - 4 * sizeof(syscall_ptr_t) - 2 * sizeof(long)) / (sizeof(syscall_ptr_t) + sizeof(void *)))
#define SYSCALL_MAX_RQUEUE_SIZE	(SYSCALL_MAX_PTHREADS * (sizeof(syscall_ptr_t) + sizeof(void *)) + 4 * sizeof(syscall_ptr_t) + 2 * sizeof(long))

struct syscall_queue {
	syscall_ptr_t alloc_head;
	syscall_ptr_t alloc_tail;
	syscall_ptr_t free_head;
	syscall_ptr_t free_tail;
	syscall_ptr_t next[SYSCALL_MAX_PTHREADS];
	void *entries[SYSCALL_MAX_PTHREADS];
	unsigned long waiters;
	unsigned long nkthreads;
	char _pad[SYSCALL_QUEUE_PAGES * PAGE_SIZE - SYSCALL_MAX_RQUEUE_SIZE];
};

#define SYSCALL_MAX_ENTRIES		((SYSCALL_CALL_PAGES * PAGE_SIZE - 2 * sizeof(syscall_ptr_t)) / (sizeof(syscall_entry_t) + sizeof(size_t)))
#define SYSCALL_MAX_CALL_SIZE	(SYSCALL_MAX_ENTRIES * sizeof(syscall_entry_t) + 2 * sizeof(syscall_ptr_t) + SYSCALL_MAX_ENTRIES * sizeof(size_t))

typedef struct syscall_page {
	syscall_entry_t	entry[SYSCALL_MAX_ENTRIES];
	syscall_ptr_t alloc_top;
	syscall_ptr_t free_top;
	size_t next[SYSCALL_MAX_ENTRIES];
	char _pad[SYSCALL_CALL_PAGES * PAGE_SIZE - SYSCALL_MAX_CALL_SIZE];
} syscall_page_t;

#define SYSCALL_WAKE_REQUESTED		0x100000000ULL
#define SYSCALL_WAKE_IN_PROGRESS	0x80000000U

typedef struct syscall_wake_page {
	volatile uint64_t running_threads;
	char _pad[PAGE_SIZE - sizeof(uint64_t)];
} syscall_wake_page_t;

#ifdef __cplusplus
}
#endif

#endif /* !_SYSCALL_COMMON_SYSCALL_H */
