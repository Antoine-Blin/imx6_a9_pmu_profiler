obj-m += profiler.o
profiler-y := main.o v7_debug.o interface.o

all:
	make -C /$(ROOTFS)/build/ M=$(PWD) modules

clean:
	make -C /$(ROOTFS)/build/ M=$(PWD) clean
