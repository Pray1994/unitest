obj-m:=nfsample.o nfsample_in.o
nfsample-objs:=unittest.o
nfsample_in-objs:=unittest_in.o
KERNELBUILD:=/lib/modules/`uname -r`/build

DEBUG = y
ifeq ($(DEBUG),y)
	DEBFLAGS = -g -O0
else
	DEBFLAGS = -O2
endif
EXTRA_CFLAGS += $(DEBFLAGS)

default: 
	./dos2unix unittest.c
	./dos2unix unittest_in.c
	./dos2unix Makefile
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o *.ko *.mod *.mod.c .tmp_versions *.order *.symvers *.unsigned .*.cmd 
install:
	insmod nfsample.ko
	insmod nfsample_in.ko
uninstall:
	rmmod nfsample.ko nfsample_in.ko
