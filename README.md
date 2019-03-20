# VirtuOS

Copyright (C) 2012-2013 Ruslan Nikolaev

**_Note: It was last released in 2013; I mirrored it here on GitHub._**

VirtuOS R1.0x requires Linux 3.2.30, Xen 4.2.0, uClibc 0.9.33, and libaio 0.3.109. VirtuOS requires x86\_64 installation.

There is also a [patch](https://lists.xen.org/archives/html/xen-devel/2012-03/msg00678.html) to solve memory leaks with grant tables.
I adopted it to Linux 3.2.30, so that it can work with VirtuOS, see
linux\_memleak.patch

Copyright and license info can be obtained directly from new and updated files.

## VirtuOS R1.01

VirtuOS R1.01 contains some fixes and improvements.

## Publication

[Paper](https://dl.acm.org/ft_gateway.cfm?id=2522719)

**VirtuOS: An Operating System with Kernel Virtualization.** Ruslan Nikolaev and Godmar Back. In Proceedings of the 24th ACM Symposium on Operating Systems Principles (SOSP'13), pp.116-132. Farmington, PA, USA.

## Installation

Installation requires patching & compiling many components. Exact building procedures for Linux and Xen will depend on Linux distribution you use. Please note that VirtuOS relies on uClibc. Consequently, we only recommend distributions that use uClibc as their default C library (e.g., Alpine Linux.) Below we provide generic instructions.

Although VirtuOS is binary compatible with Linux/uClibc, adjustments are necessary when TLS (thread local storage) is used. Please make sure to compile all programs that use TLS (including uClibc and libaio) with -mno-tls-direct-seg-refs GCC option. For simplicity, you can use a wrapper for gcc:

```
#!/bin/sh
exec /usr/bin/gcc_original "$@" "-mno-tls-direct-seg-refs"
```

**_Note that VirtuOS installation and usage may make your system unbootable or even corrupt your system and data. We highly recommend that you make a backup copy of your system and data. It is also a very good idea to have a dedicated Linux installation and partition(s) for VirtuOS. Also, since VirtuOS is only a prototype, it is not designed for normal daily use — do not use it for any critical work and do not access/modify critical data. The code is provided AS IS without any guarantees, we are not responsible/liable for any damage and/or data loss!_**

1. Build & install Linux (e.g., make menuconfig). Before building make sure to integrate all patches. Make sure to update headers in the path which will be used to build uClibc and libaio because new system calls are introduced in the patches. This is particularly important if you build it through system package manager; in this case you may also need to integrate patches into linux-headers package.

```
tar xvpf linux-3.2.30.tar.xz
cd linux-3.2.30
patch -p1 < ../linux.patch
patch -p1 < ../linux_memleak.patch
```

2. Build & install Xen. Before building make sure to integrate all patches.

```
tar xvpf xen-4.2.0.tar.gz
cd xen-4.2.0
patch -p1 < ../xen.patch
```

3. Compile and install backend and frontend drivers from corresponding packages. Frontend driver should reside in the primary domain, while backend drivers -- in corresponding service domains. You must use correct headers and Linux path, so that modules are compiled for the above-mentioned version of Linux.

```
cd syscall-frontend
make
cd ../syscall-backend
cd network
make
cd ../storage
make
```

4. Prepare a separate file system for VirtuOS. This is needed to substitute all system libraries and binaries (including dynamic linker). This can be done by copying all crucial files and directories (/bin, /lib, /usr, /etc, /sbin and others) to a dedicated empty directory (e.g., /usr/sclib -- do not copy /usr/sclib recursively while copying /usr). Also create empty directories inside /usr/sclib for remaining directories that normally appear in /. Later on, they can be mounted to /usr/sclib as shown in the example below.

```
mount --bind /dev /usr/sclib/dev
mount --bind /home /usr/sclib/home
mount --bind /root /usr/sclib/root
mount --bind /run /usr/sclib/run
mount --bind /tmp /usr/sclib/tmp
mount --bind /media /usr/sclib/media
mount --bind /sys /usr/sclib/sys
mount --bind /proc /usr/sclib/proc
mount --bind /var /usr/sclib/var
```

5. Build C library. Do not replace your standard C library in the default system path! If you update your normal standard library, your system will become unbootable and very hard to fix. Instead, install it to the dedicated location you created in step 4 by specifying building/installation prefix such as /usr/sclib

```
tar xvpf uClibc-0.9.33.tar.xz
cd uClibc-0.9.33
patch -p1 < ../uclibc.patch
```

6. Build libaio library. Do not replace your standard libaio library in the default system path! If you update your normal standard library, your system will become unbootable and very hard to fix. Instead, install it to the dedicated location you created in step 4 by specifying building/installation prefix such as /usr/sclib

```
tar xvpf libaio-0.3.109.tar.bz2
cd libaio-0.3.109
patch -p1 < ../libaio.patch
```

7. Build syscall control utility.

```
cd syscall-utils
make
```

## Usage

Please make sure that Xen has sufficient number of inter-domain sharable pages. (e.g., specify gnttab\_max\_nr\_frames=8192).

1. Boot up primary domain (compiled Linux and Xen) and service domains (compiled Linux, HVM mode). Make sure to configure domains correctly (e.g., PCI passthrough).
2. Load frontend driver in the primary domain and backend drivers in the corresponding service domains.
3. Connect to all service domains using syscall utility. (Root privileges are required.)

```
syscall all start
```

4. Mount necessary directories to /usr/sclib (See above.)
5. Change root directory. (Root privileges are required.)

```
chroot /usr/sclib
```

6. Now everything in /usr/sclib will appear as /. You can launch programs; they will use new C, pthread, libaio libraries, dynamic linker, etc.
