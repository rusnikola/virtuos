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

#ifndef _SYSCALL_COMMON_FILE_H
#define _SYSCALL_COMMON_FILE_H	1

#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/atomic.h>
#include <linux/sched.h>

static inline int write_efd_task(unsigned int fd, struct task_struct *task)
{
	struct file *file = NULL;
	loff_t pos = 0;
	ssize_t size;
	uint64_t val = 1;

	task_lock(task);
	if (task->files)
		file = fget_task(fd, task);
	task_unlock(task);
	if (unlikely(file == NULL))
		return -EBADF;
	size = vfs_write(file, (char *) &val, sizeof(uint64_t), &pos);
	fput(file);
	if (unlikely(size != sizeof(uint64_t)))
		return -EFAULT;
	return 0;
}

#endif /* !_SYSCALL_COMMON_FILE_H */
