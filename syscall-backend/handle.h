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

#ifndef _SYSCALL_BACKEND_HANDLE_H
#define _SYSCALL_BACKEND_HANDLE_H	1

#include "backend.h"

#include <linux/syscalls.h>
#include <linux/ioctl.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/eventpoll.h>
#include <linux/eventfd.h>
#include <linux/termios.h>
#include <linux/utsname.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <linux/slab.h>
#include <asm/poll.h>
#include <asm/io.h>

#ifndef EPOLLIN
# define EPOLLIN	0x1
#endif

#ifdef SYSCALL_DEBUG
# define SYSCALL_TRACE_CALL(id) \
	char *__debug_ptr, __debug_buf[384]; \
	__debug_ptr = __debug_buf; \
	printk(KERN_WARNING "CALL: " #id "\n"); \
	__debug_ptr += sprintf(__debug_ptr, KERN_INFO "[SYSCALL_TRACE %u:%u] CALL " #id "\n", current->tgid, current->pid);
# define SYSCALL_TRACE_RESULT(result)	\
	__debug_ptr += sprintf(__debug_ptr, "	[R]: %li\n", result); \
	printk(__debug_buf);
# define SYSCALL_TRACE_ARGS0
# define SYSCALL_TRACE_ARGS1	\
	SYSCALL_TRACE_ARGS0			\
	__debug_ptr += sprintf(__debug_ptr, "	[0]: %li\n", entry->args[0]); 
# define SYSCALL_TRACE_ARGS2	\
	SYSCALL_TRACE_ARGS1			\
	__debug_ptr += sprintf(__debug_ptr, "	[1]: %li\n", entry->args[1]);
# define SYSCALL_TRACE_ARGS3	\
	SYSCALL_TRACE_ARGS2			\
	__debug_ptr += sprintf(__debug_ptr, "	[2]: %li\n", entry->args[2]);
# define SYSCALL_TRACE_ARGS4	\
	SYSCALL_TRACE_ARGS3			\
	__debug_ptr += sprintf(__debug_ptr, "	[3]: %li\n", entry->args[3]);
# define SYSCALL_TRACE_ARGS5	\
	SYSCALL_TRACE_ARGS4			\
	__debug_ptr += sprintf(__debug_ptr, "	[4]: %li\n", entry->args[4]);
# define SYSCALL_TRACE_ARGS6	\
	SYSCALL_TRACE_ARGS5			\
	__debug_ptr += sprintf(__debug_ptr, "	[5]: %li\n", entry->args[5]);
#else
# define SYSCALL_TRACE_CALL(id)
# define SYSCALL_TRACE_RESULT(result)		;
# define SYSCALL_TRACE_ARGS0
# define SYSCALL_TRACE_ARGS1
# define SYSCALL_TRACE_ARGS2
# define SYSCALL_TRACE_ARGS3
# define SYSCALL_TRACE_ARGS4
# define SYSCALL_TRACE_ARGS5
# define SYSCALL_TRACE_ARGS6
#endif

#define SYSCALL_ENTRY_BEGIN(id, args)			\
	case __NRR_##id:							\
	{											\
		__label__ error;						\
		SYSCALL_TRACE_CALL(id)					\
		SYSCALL_TRACE_ARGS##args				\
		{										\

#define SYSCALL_ENTRY_END						\
		}										\
	error: __attribute__ ((unused))				\
		SYSCALL_TRACE_RESULT(result)			\
		break;									\
	}

/* The main system call handler routine */
static inline long syscall_handle(struct syscall_thread_group *data, syscall_entry_t *entry, unsigned int id)
{
	long result;
	const struct cred *cred;

	switch (id)
	{
		SYSCALL_ENTRY_BEGIN(io_setup, 2)
			// Not needed currently
			//result = sys_io_setup(entry->args[0], &entry->args[1]);
			result = 0;
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(io_destroy, 1)
			// Not needed currently
			//result = sys_io_destroy(entry->args[0]);
			result = 0;
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(io_cancel, 3)
			result = sys_io_cancel(entry->args[0], (struct iocb *) entry->args[1], (struct io_event *) entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(io_submit, 3)
			result = sys_io_submit(entry->args[0], entry->args[1], (struct iocb **) entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setuid, 1)
			task_lock(current);
			result = sys_setuid(entry->args[0]);
			cred = get_current_cred();
			task_unlock(current);
			syscall_sync_cred(data, cred);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setgid, 1)
			task_lock(current);
			result = sys_setgid(entry->args[0]);
			cred = get_current_cred();
			task_unlock(current);
			syscall_sync_cred(data, cred);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setreuid, 2)
			task_lock(current);
			result = sys_setreuid(entry->args[0], entry->args[1]);
			cred = get_current_cred();
			task_unlock(current);
			syscall_sync_cred(data, cred);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setregid, 2)
			task_lock(current);
			result = sys_setregid(entry->args[0], entry->args[1]);
			cred = get_current_cred();
			task_unlock(current);
			syscall_sync_cred(data, cred);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setresuid, 3)
			task_lock(current);
			result = sys_setresuid(entry->args[0], entry->args[1], entry->args[2]);
			cred = get_current_cred();
			task_unlock(current);
			syscall_sync_cred(data, cred);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setresgid, 2)
			task_lock(current);
			result = sys_setresgid(entry->args[0], entry->args[1], entry->args[2]);
			cred = get_current_cred();
			task_unlock(current);
			syscall_sync_cred(data, cred);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(uname, 1)
			result = sys_newuname((struct new_utsname *) entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(capset, 2)
			result = sys_capset((struct __user_cap_header_struct *) entry->args[0], (struct __user_cap_data_struct *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(sethostname, 2)
			result = sys_sethostname((char *) entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setdomainname, 2)
			result = sys_setdomainname((char *) entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(prctl, 5)
			if (entry->args[0] != PR_CAPBSET_DROP) {
				result = -EINVAL;
				goto error;
			}
			task_lock(current);
			result = sys_prctl(entry->args[0], entry->args[1], entry->args[2],
				entry->args[3], entry->args[4]);
			cred = get_current_cred();
			task_unlock(current);
			syscall_sync_cred(data, cred);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setgroups, 2)
			task_lock(current);
			result = sys_setgroups(entry->args[0], (gid_t *) entry->args[1]);
			cred = get_current_cred();
			task_unlock(current);
			syscall_sync_cred(data, cred);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(eventfd, 1)
			result = sys_eventfd(entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(syscall_service_init, 1)
			long old_efd = entry->args[0];
			if (old_efd >= 0)
				sys_close(old_efd);
			result = sys_eventfd2(0, EFD_SEMAPHORE);
			if (old_efd >= 0)
				data->init_efd = result;
			syscall_entry_result_upper(entry) = (unsigned long) data->page;
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(eventfd2, 2)
			result = sys_eventfd2(entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(epoll_create, 1)
			result = sys_epoll_create(entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(epoll_create1, 1)
			result = sys_epoll_create1(entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(epoll_ctl, 5)
			struct epoll_event event;
			event.events = entry->args[3];
			event.data = entry->args[4];
			result = do_epoll_ctl(entry->args[0], entry->args[1],
				entry->args[2], &event);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fdatasync, 1)
			result = sys_fdatasync(entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(flock, 2)
			result = sys_flock(entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fsync, 1)
			result = sys_fsync(entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fadvise64, 4)
			result = sys_fadvise64(entry->args[0], entry->args[1],
				entry->args[2], entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fstat, 2)
			result = sys_newfstat(entry->args[0], (struct stat *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(stat, 2)
			result = sys_newstat((const char *) entry->args[0], (struct stat *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(lstat, 2)
			result = sys_newlstat((const char *) entry->args[0], (struct stat *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(newfstatat, 4)
			result = sys_newfstatat(entry->args[0], (char *) entry->args[1], (struct stat *) entry->args[2], entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(dup, 1)
			result = sys_dup(entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(splice, 6)
			/* Here we assume that sizeof(long) == sizeof(loff_t) */
			result = sys_splice(entry->args[0], entry->args[1] != -1L ?
				(loff_t *) &entry->args[1] : NULL, entry->args[2],
				entry->args[3] != -1L ? (loff_t *) &entry->args[3] : NULL,
				entry->args[4], entry->args[5]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(sendfile, 4)
			/* Here we assume that sizeof(long) == sizeof(loff_t) */
			result = sys_sendfile64(entry->args[0], entry->args[1],
				entry->args[2] != -1L ? (loff_t *) &entry->args[2] : NULL,
				entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(syscall_service_select, 5)
			unsigned long nfds;
			long efd_pair, efd_local, efd;

			nfds = entry->args[0] >> 20;
			efd_pair = entry->args[0] & 0xFFFFF;
			result = sys_select(nfds, (fd_set *) entry->args[1],
				(fd_set *) entry->args[2], (fd_set *) entry->args[3],
				(struct timeval *) entry->args[4]);
			if (efd_pair != 0xFFFFF) {
				efd_local = efd_pair >> 10;
				efd = efd_pair & 0x3FF;
				syscall_backend_notify_done(efd_local, data->tgid, entry->task_id);
				/* Just read to any user memory */
				if (sys_read(efd, (char *) &entry->args[4],
					sizeof(uint64_t)) != sizeof(uint64_t)) {
					result = -EFAULT;
				}
			}
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(syscall_service_poll, 3)
			unsigned long nfds;
			long efd_pair, efd, efd_local;

			nfds = entry->args[1] >> 20;
			efd_pair = entry->args[1] & 0xFFFFF;
			result = sys_poll((struct pollfd *) entry->args[0], nfds,
				entry->args[2]);
			if (efd_pair != 0xFFFFF) {
				efd_local = efd_pair >> 10;
				efd = efd_pair & 0x3FF;
				syscall_backend_notify_done(efd_local, data->tgid, entry->task_id);
				/* Just read to any user memory */
				if (sys_read(efd, (char *) &entry->args[4],
					sizeof(uint64_t)) != sizeof(uint64_t)) {
					result = -EFAULT;
				}
			}
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(syscall_service_epoll_wait, 4)
			struct epoll_event event_efd;
			unsigned long epfd;
			long efd_pair, efd, efd_local;

			epfd = entry->args[0] >> 20;
			efd_pair = entry->args[0] & 0xFFFFF;
			if (efd_pair != 0xFFFFF) {
				efd_local = efd_pair >> 10;
				efd = efd_pair & 0x3FF;
				event_efd.events = EPOLLIN | EPOLLEFD;
				event_efd.data = 0;
				do_epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &event_efd);
				result = sys_epoll_wait(epfd, (struct epoll_event *) entry->args[1], entry->args[2], entry->args[3]);
				syscall_backend_notify_done(efd_local, data->tgid, entry->task_id);
				do_epoll_ctl(epfd, EPOLL_CTL_DEL, efd, &event_efd);
				/* Just read to any user memory */
				if (sys_read(efd, (char *) &entry->args[4],
					sizeof(uint64_t)) != sizeof(uint64_t)) {
					result = -EFAULT;
				}
			} else {
				result = sys_epoll_wait(epfd, (struct epoll_event *) entry->args[1], entry->args[2], entry->args[3]);
			}
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(read, 3)
			result = sys_read(entry->args[0], (void *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(write, 3)
			result = sys_write(entry->args[0], (void *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(pread64, 4)
			result = sys_pread64(entry->args[0], (void *) entry->args[1], entry->args[2], entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(pwrite64, 4)
			result = sys_pwrite64(entry->args[0], (void *) entry->args[1], entry->args[2], entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(close, 1)
			result = sys_close(entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(shutdown, 2)
			result = sys_shutdown(entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(ioctl, 3)
			result = sys_ioctl(entry->args[0], entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fcntl, 3)
			result = sys_fcntl(entry->args[0], entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(socket, 3)
			result = sys_socket(entry->args[0], entry->args[1] | SOCK_NOSIGNAL, entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(listen, 2)
			result = sys_listen(entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(accept, 3)
			/* 3rd parameter will also be upper word result */
			result = sys_accept4(entry->args[0], (struct sockaddr *) entry->args[2], entry->args[2] ? SYSCALL_INT_PTR(&entry->args[1]) : NULL, SOCK_NOSIGNAL);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(accept4, 4)
			/* 3rd parameter will also be upper word result */
			result = sys_accept4(entry->args[0], (struct sockaddr *) entry->args[2], entry->args[2] ? SYSCALL_INT_PTR(&entry->args[1]) : NULL, entry->args[3] | SOCK_NOSIGNAL);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(getsockname, 3)
			/* 3rd parameter will also be upper word result */
			result = sys_getsockname(entry->args[0], (struct sockaddr *) entry->args[2], SYSCALL_INT_PTR(&entry->args[1]));
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(getpeername, 3)
			/* 3rd parameter will also be upper word result */
			result = sys_getpeername(entry->args[0], (struct sockaddr *) entry->args[2], SYSCALL_INT_PTR(&entry->args[1]));
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(getsockopt, 5)
			/* 5th parameter will also be upper word result */
			result = sys_getsockopt(entry->args[0], entry->args[4],
				entry->args[2], (void *) entry->args[3],
				SYSCALL_INT_PTR(&entry->args[1]));
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(setsockopt, 5)
			result = sys_setsockopt(entry->args[0], entry->args[4],
				entry->args[2], (void *) entry->args[3], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(bind, 3)
			result = sys_bind(entry->args[0], (struct sockaddr *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(connect, 3)
			result = sys_connect(entry->args[0], (struct sockaddr *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(sendto, 6)
			result = sys_sendto(entry->args[0],
				(void *) entry->args[5], entry->args[2], entry->args[3],
				(struct sockaddr *) entry->args[4], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(recvfrom, 6)
			/* 6th parameter will also be upper word result */
			result = sys_recvfrom(entry->args[0],
				(void *) entry->args[5], entry->args[2], entry->args[3],
				(struct sockaddr *) entry->args[4], entry->args[4] ?
				SYSCALL_INT_PTR(&entry->args[1]) : NULL);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(sendmsg, 3)
			result = sys_sendmsg(entry->args[0], (struct msghdr *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(recvmsg, 3)
			result = sys_recvmsg(entry->args[0], (struct msghdr *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(syscall_service_chdir, 3)
			result = sys_syscall_service_chdir((const char *) entry->args[0], (char *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(syscall_service_fchdir, 3)
			result = sys_syscall_service_fchdir(entry->args[0], (char *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(symlink, 2)
			result = sys_symlink((const char *) entry->args[0], (const char *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(readlink, 3)
			result = sys_readlink((const char *) entry->args[0], (char *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(link, 2)
			result = sys_link((const char *) entry->args[0], (const char *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(rename, 2)
			result = sys_rename((const char *) entry->args[0], (const char *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(chmod, 2)
			result = sys_chmod((const char *) entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fchmod, 2)
			result = sys_fchmod(entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(truncate, 2)
			result = sys_truncate((const char *) entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(ftruncate, 2)
			result = sys_ftruncate(entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(open, 3)
			result = sys_open((const char *) entry->args[0], entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(chown, 3)
			result = sys_chown((const char *) entry->args[0], entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(lchown, 3)
			result = sys_lchown((const char *) entry->args[0], entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fchown, 3)
			result = sys_fchown(entry->args[0], entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(lseek, 3)
			result = sys_lseek(entry->args[0], entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(statfs, 2)
			result = sys_statfs((const char *) entry->args[0], (struct statfs *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fstatfs, 2)
			result = sys_fstatfs(entry->args[0], (struct statfs *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(unlink, 1)
			result = sys_unlink((const char *) entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(mknod, 3)
			result = sys_mknod((const char *) entry->args[0], entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(mkdir, 2)
			result = sys_mkdir((const char *) entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(rmdir, 1)
			result = sys_rmdir((const char *) entry->args[0]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(faccessat, 3)
			result = sys_faccessat(entry->args[0], (const char *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fchmodat, 3)
			result = sys_fchmodat(entry->args[0], (const char *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(fchownat, 5)
			result = sys_fchownat(entry->args[0], (const char *) entry->args[1], entry->args[2], entry->args[3], entry->args[4]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(futimesat, 3)
			result = sys_futimesat(entry->args[0], (const char *) entry->args[1], (struct timeval *) entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(mkdirat, 3)
			result = sys_mkdirat(entry->args[0], (const char *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(mknodat, 4)
			result = sys_mknodat(entry->args[0], (const char *) entry->args[1], entry->args[2], entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(unlinkat, 3)
			result = sys_unlinkat(entry->args[0], (const char *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(readlinkat, 4)
			result = sys_readlinkat(entry->args[0], (const char *) entry->args[1], (char *) entry->args[2], entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(symlinkat, 3)
			result = sys_symlinkat((const char *) entry->args[0], entry->args[1], (const char *) entry->args[2]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(linkat, 5)
			result = sys_linkat(entry->args[0], (const char *) entry->args[1], entry->args[2], (const char *) entry->args[3], entry->args[4]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(renameat, 4)
			result = sys_renameat(entry->args[0], (const char *) entry->args[1], entry->args[2], (const char *) entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(utimensat, 4)
			result = sys_utimensat(entry->args[0], (const char *) entry->args[1], (struct timespec *) entry->args[2], entry->args[3]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(utime, 2)
			result = sys_utime((char *) entry->args[0], (struct utimbuf *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(utimes, 2)
			result = sys_utimes((char *) entry->args[0], (struct timeval *) entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(access, 2)
			result = sys_access((const char *) entry->args[0], entry->args[1]);
		SYSCALL_ENTRY_END

		SYSCALL_ENTRY_BEGIN(getdents64, 3)
			result = sys_getdents64(entry->args[0], (struct linux_dirent64 *) entry->args[1], entry->args[2]);
		SYSCALL_ENTRY_END

		default:
		{
			SYSCALL_TRACE_CALL(unknown)
			SYSCALL_TRACE_ARGS6
			result = -EINVAL;
			SYSCALL_TRACE_RESULT(result)
			break;
		}
	}

	return result;
}

#endif /* !_SYSCALL_BACKEND_HANDLE_H */
