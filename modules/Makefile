KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$(PWD)

load:
	sudo insmod krdma.ko debug=1

make unload:
	sudo rmmod krdma.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help
