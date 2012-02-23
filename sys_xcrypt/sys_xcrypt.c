/*--Start of sys_xcrypt.c--*/
#include<linux/linkage.h>
#include<linux/kernel.h>
extern int (*function_pointer)(char *, char *, char*, int, int);
asmlinkage long sys_xcrypt(char *infile, char* outfile, char* keybuf, int keylen, int flags){

	//function_pointer=function;
	printk("Function called");
	if (function_pointer == 0){
		printk("The function pointer is NULL\n");
		return -1;
	}
printk("The function pointer is not null\n");
return (*function_pointer)(infile, outfile, keybuf,  keylen, flags);
}
/*--End of sys_xcrypt.c--*/
