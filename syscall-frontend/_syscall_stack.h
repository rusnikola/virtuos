/**
 * VM-Syscalls
 * Copyright (c) 2012-2013 Ruslan Nikolaev
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

#ifndef _SYSCALL_COMMON_SYSCALL_STACK_H
#define _SYSCALL_COMMON_SYSCALL_STACK_H 1

#include "_dcmpxchg.h"
#include "_syscall_defs.h"

/* This implements LIFO queue. */
static inline void syscall_stack_push(size_t *next, syscall_ptr_t *top, size_t eidx)
{
	syscall_ptr_t prev_top;

	do {
		prev_top = VOLATILE_READ(*top);
		next[eidx] = prev_top.index;
	} while (!dcmpxchg(&top->index, prev_top.index, prev_top.stamp, eidx, prev_top.stamp + 1));
}

static inline size_t syscall_stack_pop(size_t *next, syscall_ptr_t *top, size_t max)
{
	syscall_ptr_t prev_top;
	size_t next_top;

	do {
		prev_top = VOLATILE_READ(*top);
		if (prev_top.index == SYSCALL_NULL_ENTRY) {
			return SYSCALL_NULL_ENTRY;
		}
		if (unlikely(prev_top.index >= max)) {
			return SYSCALL_ERROR_ENTRY;
		}
		next_top = VOLATILE_READ(next[prev_top.index]);
	} while (!dcmpxchg(&top->index, prev_top.index, prev_top.stamp, next_top, prev_top.stamp + 1));

	return prev_top.index;
}

static inline size_t syscall_stack_check(syscall_ptr_t *top, size_t max)
{
	syscall_ptr_t cur_top;

	cur_top = VOLATILE_READ(*top);
	if (cur_top.index == SYSCALL_NULL_ENTRY) {
		return SYSCALL_NULL_ENTRY;
	}
	if (unlikely(cur_top.index >= max)) {
		return SYSCALL_ERROR_ENTRY;
	}
	return 0;
}

#endif /* !_SYSCALL_COMMON_SYSCALL_STACK_H */
