obj-m += netstack.o

# Find all .c files in src/ and map them to .o
SRCS := $(wildcard src/*.c)
netstack-y := $(patsubst %.c,%.o,$(SRCS))

# Use ccflags-y so modern Kbuild passes the include directory
ccflags-y := -I$(src)/include

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: all clean test

all: test
	$(MAKE) -C $(KDIR) M=$(PWD) modules

test: test/test_client.c
	gcc -Wall -Wextra -O2 -I$(PWD)/include test/test_client.c -o test_client

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f test_client