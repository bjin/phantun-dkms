KVER ?= $(shell uname -r)
KDIR ?= $(patsubst %/,%,$(dir $(firstword $(wildcard \
 	/lib/modules/$(KVER)/build/Makefile \
 	/run/current-system/kernel-modules/lib/modules/$(KVER)/build/Makefile \
 	/nix/store/*-linux-$(KVER)-dev/lib/modules/$(KVER)/build/Makefile \
 	/nix/store/*linux-$(KVER)-dev/lib/modules/$(KVER)/build/Makefile))))
PWD := $(shell pwd)

ifeq ($(strip $(KDIR)),)
$(error Unable to locate a kernel build tree; set KDIR=/path/to/kernel/build)
endif

.PHONY: all modules modules_install clean

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
