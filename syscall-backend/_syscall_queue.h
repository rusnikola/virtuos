/**
 * VM-Syscalls
 * Copyright (c) 2013 Ruslan Nikolaev
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

#ifndef _SYSCALL_COMMON_SYSCALL_QUEUE_H
#define _SYSCALL_COMMON_SYSCALL_QUEUE_H 1

#include "_dcmpxchg.h"
#include "_syscall_defs.h"

/* This implements FIFO queue. */
static inline size_t syscall_queue_enqueue(syscall_ptr_t *next,
	syscall_ptr_t *tail, size_t eidx, size_t max, bool mark)
{
	syscall_ptr_t last, succ, tmp;

	/* Initialize new entry */
	do {
		succ = VOLATILE_READ(next[eidx]);
	} while (!dcmpxchg(&next[eidx].index, succ.index, succ.stamp,
		SYSCALL_NULL_ENTRY, succ.stamp + 1));

	while (1) {
		last = VOLATILE_READ(*tail);
		if (unlikely(last.index >= max))
			return SYSCALL_ERROR_ENTRY;
		succ = VOLATILE_READ(next[last.index]);
		tmp = VOLATILE_READ(*tail);
		if (last.index != tmp.index || last.stamp != tmp.stamp)
			continue;
		if ((ssize_t) succ.index < 0) {
			if (mark && succ.index != SYSCALL_NULL_ENTRY) {
				if (dcmpxchg(&next[last.index].index, succ.index, succ.stamp,
					succ.index + 1, succ.stamp + 1)) {
					return SYSCALL_NULL_ENTRY;
				}
			} else if (dcmpxchg(&next[last.index].index, succ.index, succ.stamp,
				eidx, succ.stamp + 1))
			{
				dcmpxchg(&tail->index, last.index, last.stamp,
					eidx, last.stamp + 1);
				return 0;
			}
		} else {
			dcmpxchg(&tail->index, last.index, last.stamp, succ.index,
				last.stamp + 1);
		}
	}
}

#define syscall_queue_enqueue_fault(next, tail, eidx, max, mark) ({	\
	syscall_ptr_t *__next = (next), *__tail = (tail); \
	size_t __ret, __eidx = (eidx), __max = (max); \
	bool __mark = (mark), __dret; \
	syscall_ptr_t __last, __succ, __tmp; \
	do { \
		__succ = VOLATILE_READ_FAULT_PTR(__next[__eidx]); \
		if (__dcmpxchg_user(__dret, __succ.index, __succ.stamp, \
			SYSCALL_NULL_ENTRY, __succ.stamp + 1, &__next[__eidx].index)) \
			goto error_fault; \
	} while (!__dret); \
	while (1) { \
		__last = VOLATILE_READ_FAULT_PTR(*__tail); \
		if (unlikely(__last.index >= __max)) { \
			__ret = SYSCALL_ERROR_ENTRY; \
			break; \
		} \
		__succ = VOLATILE_READ_FAULT_PTR(__next[__last.index]); \
		__tmp = VOLATILE_READ_FAULT_PTR(*__tail); \
		if (__last.index != __tmp.index || __last.stamp != __tmp.stamp) \
			continue; \
		if ((ssize_t) __succ.index < 0) { \
			if (__mark && __succ.index != SYSCALL_NULL_ENTRY) { \
				if (__dcmpxchg_user(__dret, __succ.index, __succ.stamp, \
					__succ.index + 1, __succ.stamp + 1, \
					&__next[__last.index].index)) \
					goto error_fault; \
				if (__dret) { \
					__ret = SYSCALL_NULL_ENTRY; \
					break; \
				} \
			} else { \
				if (__dcmpxchg_user(__dret, __succ.index, __succ.stamp, \
					__eidx, __succ.stamp + 1, &__next[__last.index].index)) \
					goto error_fault; \
				if (__dret) { \
					if (__dcmpxchg_user(__dret, __last.index, __last.stamp, \
						__eidx, __last.stamp + 1, &__tail->index)) \
						goto error_fault; \
					__ret = 0; \
					break; \
				} \
			} \
		} else { \
			if (__dcmpxchg_user(__dret, __last.index, __last.stamp, \
				__succ.index, __last.stamp + 1, &__tail->index)) \
				goto error_fault; \
		} \
	} \
__ret; })

#define syscall_queue_dequeue(next, entries, head, tail, result, max, mark) ({ \
	syscall_ptr_t *__next, *__head, *__tail; \
	syscall_ptr_t __first, __last, __succ, __tmp; \
	size_t __eidx; \
	__next = (next); \
	__head = (head); \
	__tail = (tail); \
	while (1) { \
		__first = VOLATILE_READ(*__head); \
		__last = VOLATILE_READ(*__tail); \
		if (unlikely(__first.index >= max)) { \
			__eidx = SYSCALL_ERROR_ENTRY; \
			break; \
		} \
		__succ = VOLATILE_READ(__next[__first.index]); \
		__tmp = VOLATILE_READ(*__head); \
		if (__first.index != __tmp.index || __first.stamp != __tmp.stamp) \
			continue; \
		if (__first.index == __last.index) { \
			if ((ssize_t) __succ.index < 0) { \
				if (mark) { \
					if (!dcmpxchg(&__next[__first.index].index, __succ.index, __succ.stamp, __succ.index - 1, __succ.stamp + 1)) \
						continue; \
				} \
				__eidx = SYSCALL_NULL_ENTRY; \
				break; \
			} \
			dcmpxchg(&__tail->index, __last.index, __last.stamp, __succ.index, __last.stamp + 1); \
		} else { \
			if (unlikely(__succ.index >= max)) { \
				__eidx = SYSCALL_ERROR_ENTRY; \
				break; \
			} \
			*(result) = (entries)[__succ.index]; \
			if (dcmpxchg(&__head->index, __first.index, __first.stamp, \
				__succ.index, __first.stamp + 1)) { \
				__eidx = __first.index; \
				break; \
			} \
		} \
	} \
__eidx; })

#define syscall_queue_dequeue_fault(next, entries, head, tail, result, max, mark) ({ \
	syscall_ptr_t *__next, *__head, *__tail; \
	syscall_ptr_t __first, __last, __succ, __tmp; \
	size_t __eidx; \
	bool __dret; \
	__next = (next); \
	__head = (head); \
	__tail = (tail); \
	while (1) { \
		__first = VOLATILE_READ_FAULT_PTR(*__head); \
		__last = VOLATILE_READ_FAULT_PTR(*__tail); \
		if (unlikely(__first.index >= max)) { \
			__eidx = SYSCALL_ERROR_ENTRY; \
			break; \
		} \
		__succ = VOLATILE_READ_FAULT_PTR(__next[__first.index]); \
		__tmp = VOLATILE_READ_FAULT_PTR(*__head); \
		if (__first.index != __tmp.index || __first.stamp != __tmp.stamp) \
			continue; \
		if (__first.index == __last.index) { \
			if ((ssize_t) __succ.index < 0) { \
				if (mark) { \
					if (__dcmpxchg_user(__dret, __succ.index, __succ.stamp, __succ.index - 1, __succ.stamp + 1, &__next[__first.index].index))	\
						goto error_fault;	\
					if (!__dret) \
						continue; \
				} \
				__eidx = SYSCALL_NULL_ENTRY; \
				break; \
			} \
			if (__dcmpxchg_user(__dret, __last.index, __last.stamp, __succ.index, __last.stamp + 1, &__tail->index)) \
				goto error_fault; \
		} else { \
			if (unlikely(__succ.index >= max)) { \
				__eidx = SYSCALL_ERROR_ENTRY; \
				break; \
			} \
			if (__get_user(*(result), &(entries)[__succ.index])) \
				goto error_fault; \
			if (__dcmpxchg_user(__dret, __first.index, __first.stamp, \
				__succ.index, __first.stamp + 1, &__head->index)) \
					goto error_fault; \
			if (__dret) { \
				__eidx = __first.index; \
				break; \
			} \
		} \
	} \
__eidx; })

static inline size_t syscall_queue_check(syscall_ptr_t *next,
	syscall_ptr_t *head, syscall_ptr_t *tail, size_t max)
{
	syscall_ptr_t first, last, succ, tmp;

	while (1) {
		first = VOLATILE_READ(*head);
		last = VOLATILE_READ(*tail);
		if (unlikely(first.index >= max))
			return SYSCALL_ERROR_ENTRY;
		succ = VOLATILE_READ(next[first.index]);
		tmp = VOLATILE_READ(*head);
		if (tmp.index != first.index || tmp.stamp != first.stamp)
			continue;
		if (first.index != last.index)
			return 0;
		if ((ssize_t) succ.index < 0)
			return SYSCALL_NULL_ENTRY;
		dcmpxchg(&tail->index, last.index, last.stamp, succ.index,
			last.stamp + 1);
	}
}

#endif /* !_SYSCALL_COMMON_SYSCALL_QUEUE_H */
