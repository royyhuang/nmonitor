monitor: monitoruser.c
	gcc -o monitoruser monitoruser.c
ifneq ($(KERNELRELEASE),) 
	obj-m += nmonitor.o
else 

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 

PWD := $(shell pwd)

default: 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

endif 

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
