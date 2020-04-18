obj-m := firewall.o
firewall-objs+= firewall_implentation.o logs_implementation.o rule_table.o stateful_fw.o hw5secws.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
