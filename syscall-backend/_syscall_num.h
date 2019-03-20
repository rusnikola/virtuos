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

#ifndef _SYSCALL_COMMON_SYSCALL_NUM_H
#define _SYSCALL_COMMON_SYSCALL_NUM_H 			1

#define __NRR_socket							0
#define __NRR_accept							1
#define __NRR_accept4							2
#define __NRR_bind								3
#define __NRR_listen							4
#define __NRR_connect							5
#define __NRR_getsockname						6
#define __NRR_getpeername						7
#define __NRR_getsockopt						8
#define __NRR_setsockopt						9
#define __NRR_sendto							10
#define __NRR_recvfrom							11
#define __NRR_sendmsg							12
#define __NRR_recvmsg							13
#define __NRR_shutdown							14
#define __NRR_uname								15
#define __NRR_sethostname						16
#define __NRR_setdomainname						17
#define __NRR_read								18
#define __NRR_write								19
#define __NRR_pread64							20
#define __NRR_pwrite64							21
#define __NRR_splice							22
#define __NRR_sendfile							23
#define __NRR_fsync								24
#define __NRR_fdatasync							25
#define __NRR_flock								26
#define __NRR_fadvise64							27
#define __NRR_fstat								28
#define __NRR_newfstatat						29
#define __NRR_syscall_service_select			30
#define __NRR_syscall_service_poll				31
#define __NRR_syscall_service_epoll_wait		32
#define __NRR_dup								33
#define __NRR_close								34
#define __NRR_fcntl								35
#define __NRR_ioctl								36
#define __NRR_syscall_service_init				37
#define __NRR_eventfd							38
#define __NRR_eventfd2							39
#define __NRR_epoll_create						40
#define __NRR_epoll_create1						41
#define __NRR_epoll_ctl							42
#define __NRR_io_setup							43
#define __NRR_io_destroy						44
#define __NRR_io_cancel							45
#define __NRR_io_submit							46
#define __NRR_setuid							47
#define __NRR_setgid							48
#define __NRR_setreuid							49
#define __NRR_setregid							50
#define __NRR_setresuid							51
#define __NRR_setresgid							52
#define __NRR_setgroups							53
#define __NRR_capset							54
#define __NRR_prctl								55
#define __NRR_syscall_service_chdir				56
#define __NRR_syscall_service_fchdir			57
#define __NRR_symlink							58
#define __NRR_readlink							59
#define __NRR_link								60
#define __NRR_rename							61
#define __NRR_chmod								62
#define __NRR_fchmod							63
#define __NRR_truncate							64
#define __NRR_ftruncate							65
#define __NRR_stat								66
#define __NRR_lstat								67
#define __NRR_open								68
#define __NRR_chown								69
#define __NRR_fchown							70
#define __NRR_lseek								71
#define __NRR_statfs							72
#define __NRR_fstatfs							73
#define __NRR_unlink							74
#define __NRR_mknod								75
#define __NRR_mkdir								76
#define __NRR_rmdir								77
#define __NRR_faccessat							78
#define __NRR_fchmodat							79
#define __NRR_fchownat							80
#define __NRR_futimesat							81
#define __NRR_mkdirat							82
#define __NRR_mknodat							83
#define __NRR_unlinkat							84
#define __NRR_readlinkat						85
#define __NRR_symlinkat							86
#define __NRR_linkat							87
#define __NRR_renameat							88
#define __NRR_utimensat							89
#define __NRR_utime								90
#define __NRR_utimes							91
#define __NRR_access							92
#define __NRR_removexattr						93
#define __NRR_lremovexattr						94
#define __NRR_fremovexattr						95
#define __NRR_listxattr							96
#define __NRR_llistxattr						97
#define __NRR_flistxattr						98
#define __NRR_getxattr							99
#define __NRR_lgetxattr							100
#define __NRR_fgetxattr							101
#define __NRR_setxattr							102
#define __NRR_lsetxattr							103
#define __NRR_fsetxattr							104
#define __NRR_lchown							105
#define __NRR_getdents64						106

/* Aliases */
#define __NRR_fstatat64							__NRR_newfstatat
#define __NRR_posix_fadvise						__NRR_fadvise64

#endif /* !_SYSCALL_COMMON_SYSCALL_NUM_H */
