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

#include "syscall.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

static void syscall_error(const char *msg, const char *reason)
{
	fprintf(stderr, "%s: [%s]. %s\n", msg, strerror(errno), reason);
	exit(1);
}

static int syscall_ioctl(unsigned int cmd, unsigned long sysid, unsigned long count)
{
	int fd, rc;

	fd = open("/dev/syscall_service", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open /dev/syscall_service: [%s]. %s\n", strerror(errno), errno == EACCES ? "Are you root?" : "Did you load frontend driver?");
		exit(1);
	}
	do {
		rc = ioctl(fd, cmd, sysid++);
		if (rc < 0)
			break;
	} while (--count != 0);
	close(fd);
	return rc;
}

static int syscall_restart(unsigned long sysid, unsigned long count)
{
	int fd, rc;
	unsigned long _sysid, _count;

	fd = open("/dev/syscall_service", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open /dev/syscall_service: [%s]. %s\n", strerror(errno), errno == EACCES ? "Are you root?" : "Did you load frontend driver?");
		exit(1);
	}
	_sysid = sysid;
	_count = count;
	do {
		ioctl(fd, SYSCALL_SERVICE_IOCTL_DISCONNECT, _sysid++);
	} while (--_count != 0);
	printf("Waiting for remote domain(s) to complete disconnection...\n");
	sleep(3);
	printf("Connecting...\n");
	do {
		rc = ioctl(fd, SYSCALL_SERVICE_IOCTL_CONNECT, sysid++);
		if (rc < 0)
			break;
	} while (--count != 0);
	close(fd);
	return rc;
}

int main(int argc, char *argv[])
{
	unsigned long sysid, count = 1;
	int rc;

	if (argc != 3)
		goto error;

	if (!strcmp(argv[1], "network")) {
		sysid = SYSCALL_SYSID_NETWORK;
	} else if (!strcmp(argv[1], "storage")) {
		sysid = SYSCALL_SYSID_STORAGE;
	} else if (!strcmp(argv[1], "all")) {
		sysid = 0;
		count = SYSCALL_SYSIDS;
	} else {
		goto error;
	}

	if (!strcmp(argv[2], "start")) {
		rc = syscall_ioctl(SYSCALL_SERVICE_IOCTL_CONNECT, sysid, count);
		if (rc < 0)
			syscall_error("Connection failed", "Is remote domain connected?");
	} else if (!strcmp(argv[2], "stop")) {
		rc = syscall_ioctl(SYSCALL_SERVICE_IOCTL_DISCONNECT, sysid, count);
		if (rc < 0)
			syscall_error("Disconnection failed", "Already disconnected?");
	} else if (!strcmp(argv[2], "restart")) {
		rc = syscall_restart(sysid, count);
		if (rc < 0)
			syscall_error("Reconnection failed", "Is remote domain connected?");
	} else if (!strcmp(argv[2], "clean")) {
		rc = syscall_ioctl(SYSCALL_SERVICE_IOCTL_CLEANUP, sysid, count);
		if (rc < 0)
			syscall_error("Remote clean up failed", "Are you still connected to the remote domain?");
	} else {

error:
		fprintf(stderr, "Usage: %s <network,storage,all> start|stop|restart|clean\n", argv[0]);
		return 1;
	}

	return 0;
}
