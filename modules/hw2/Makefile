obj-m +=hw2.o
KDIR =/usr/src/linux-4.4

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order
