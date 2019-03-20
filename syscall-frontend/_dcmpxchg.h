#ifndef _SYSCALL_COMMON_DCMPXCHG_H
#define _SYSCALL_COMMON_DCMPXCHG_H 1

/* Double CAS implementation */
# if defined(__x86_64__) || defined(__i386__)

#  if defined(__x86_64__)
#   define __DCMPXCHG "cmpxchg16b"
#  else
#   define __DCMPXCHG "cmpxchg8b"
#  endif

static inline bool dcmpxchg(size_t *addr, size_t prev_lo, size_t prev_hi,
	size_t new_lo, size_t new_hi)
{
	bool result;
	__asm__ __volatile__ ("lock " __DCMPXCHG " %0\n\t"
						  "setz %b1"
						  : "+m" (*addr), "=a" (result), "+d" (prev_hi)
						  : "a" (prev_lo), "b" (new_lo), "c" (new_hi)
						  : "cc"
	);
	return result;
}

#  undef __DCMPXCHG

# endif

#endif /* !_SYSCALL_COMMON_DCMPXCHG */
