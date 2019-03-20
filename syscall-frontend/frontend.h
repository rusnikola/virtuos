/**
 * VM-Syscalls
 * Copyright (c) 2012 Ruslan Nikolaev
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

#ifndef _SYSCALL_FRONTEND_H
#define _SYSCALL_FRONTEND_H	1

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mmu_notifier.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <xen/grant_table.h>
#include <xen/interface/io/ring.h>
#include "_syscall.h"
#include "_syscall_stack.h"

struct syscall_irq_info;

typedef struct syscall_service_private {

} syscall_service_private_t;

typedef struct syscall_manage_pte {
	struct page **pages;
} syscall_manage_pte_t;

typedef struct syscall_frontend_info {
	struct mmu_notifier mn;
	struct spinlock lock;
	uint32_t domid;
	uint32_t map_pos;
	uint32_t mmu_registered;
	uint32_t grefs[SYSCALL_TOTAL_SHARED_PAGES];
	struct vm_area_struct *vma;
	syscall_wake_page_t *wake_page;
	struct page *pages[SYSCALL_TOTAL_SHARED_PAGES];
	struct gnttab_map_grant_ref kmap_ops[SYSCALL_TOTAL_SHARED_PAGES];
	struct gnttab_unmap_grant_ref unmap_ops[SYSCALL_TOTAL_SHARED_PAGES];
} syscall_frontend_info_t;

typedef struct syscall_frontend_private {
	syscall_frontend_info_t info;
	struct mutex lock;
	pid_t tgid;
	struct syscall_irq_info *service;
	struct mm_struct *mm;
} syscall_frontend_private_t;

#endif /* !_SYSCALL_FRONTEND_H */
