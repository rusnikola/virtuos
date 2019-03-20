/**
 * VM-Syscalls
 * Copyright (c) 2013 Ruslan Nikolaev <rnikola@vt.edu>
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

#ifndef _SYSCALL_COMMON_DEFS_H
#define _SYSCALL_COMMON_DEFS_H 1

typedef struct syscall_ptr {
	size_t index; /* Must be first! */
	size_t stamp;
} __attribute__ ((aligned(sizeof(size_t) * 2))) syscall_ptr_t;

#define SYSCALL_NULL_ENTRY			(size_t) (-1L)
#define SYSCALL_ERROR_ENTRY			(size_t) (-2L)
#define SYSCALL_REPEAT_ENTRY		(size_t) (-3L)

#define VOLATILE_READ(x)		(*(volatile __typeof__(x) *) &(x))
#define VOLATILE_READ_FAULT(x) ({		\
	__typeof__(x) __r;					\
	if (__get_user(__r, &(x)) != 0)		\
		goto error_fault;				\
	__r;								\
})

#define VOLATILE_READ_FAULT_PTR(x) ({				\
	__typeof__(x) __r;								\
	if (__get_user(__r.index, &(x).index) != 0)		\
		goto error_fault;							\
	if (__get_user(__r.stamp, &(x).stamp) != 0)		\
		goto error_fault;							\
	__r;											\
})

#endif /* !_SYSCALL_COMMON_DEFS_H */
