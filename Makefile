obj-m += sys_xcrypt.o
  
all: xcipher sys_xcrypt
  
xcipher:
	gcc -Wall -Werror xcipher.c -o xcipher -lssl
sys_xcrypt:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcipher
