obj-m += syscall-backend.o
syscall-backend-objs := backend.o
ccflags-y := -DSYSCALL_SYSID_CURRENT=SYSCALL_SYSID_NETWORK

KVERSION = $(shell uname -r)
all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
