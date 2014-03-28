obj-m += firewall.o
firewall-objs := netfltrHooks.o procfsHelper.o utils.o firewall-lkm.o
all:
	make -C /usr/src/linux-headers-`uname -r` SUBDIRS=$(PWD) modules
clean:
	make -C /usr/src/linux-headers-`uname -r` SUBDIRS=$(PWD) clean
