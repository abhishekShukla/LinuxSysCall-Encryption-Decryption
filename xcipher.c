/*--Start of the C file--*/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>
#include <error.h>
#include <string.h>
#include <openssl/md5.h>
#define __NR_sys_xcrypt 349

long mycall(char* infile, char* outfile, char* keybuf, int keylen, int flags){
	return syscall(__NR_sys_xcrypt,infile,outfile,keybuf,keylen,flags);
}

int main(int argc, char **argv){
    
    char *infile = NULL; 
    char *outfile = NULL; 
    int flags = 0;
    unsigned char* res = (unsigned char*)malloc(16*sizeof(unsigned char));
    unsigned char* md = (unsigned char*)malloc(16*sizeof(unsigned char));
    int temp_looper = 0; 
    int pass_looper = 0;

    unsigned char* pass_temp = NULL;
    int encrypt = 0;
    int decrypt = 0;
    unsigned char* password = NULL;
    int help = 0;
    int option = 0; 
    int err = 1;
    unsigned long keylen = 0;
    memset(res, 0, 16);
    memset(md, 0, 16);
    
    while ((option = getopt (argc, argv, "edp:h")) != -1){
        err = 0;
        switch(option){
            case 'e':
                encrypt = 1;
                break;
            case 'd':
                decrypt = 1;
            break;
            case 'p':
                pass_temp = (unsigned char*)optarg;
                break;
            case 'h':
                help = 1;
                break;
            case '?':
                if (optopt == 'p')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n",optopt);
                    fprintf (stderr, "Please Use \"./xcrypt -h\" for help\n");
                return 1;
            default:
                help = 1;
            }
        }

    if(err)
    {
        fprintf(stderr,"ERROR: YOU ARE PROBABLY TRYING TO REDIRECT THE INPUT FROM A FILE. GET OPT FAILED!\n\n");
        help = 1;
    }
    if(help){
        printf("USAGE:\n./xcrypt [OPTIONS] [ARGUMENT] [INPUT] [OUTPUT]\nDESCRIPTION\n\tOPTIONS\n\t\t-e: Encryption\n\t\t-d: Decryption\n\t\t-p: Encryption/Decryption Key. Pass the Key as the Argument\n\t\t-h: Help\n\tINPUT\n\t\tInput File\n\tOUTPUT\n\t\tOutput File\n");
        return 0;
    }

    if(encrypt && decrypt){
        fprintf(stderr, "You have selected both Encryption and Decryption. Please select only one (-e : encryption, -d : decryption)\n");
        fprintf (stderr, "Please Use \"./xcrypt -h\" for help\n");
        return 1;
    }
    if(decrypt){
        flags = 0;
    }
    if(encrypt){
        flags = 1;
    }
    if((strlen((char*)pass_temp) < 6)){
        fprintf(stderr,"PASSWORD IS TOO SHORT. IT MUST BE ATLEAST 6 CHARACTERS LONG!\n");
        return 1;
    }
    
    password = (unsigned char*)malloc(strlen((char*)pass_temp));
    memset(password, 0, strlen((char*)pass_temp));
    
    for(temp_looper = 0; temp_looper < strlen((char*)pass_temp); temp_looper++){
        if(pass_temp[temp_looper] != '\n'){
            password[pass_looper] = pass_temp[temp_looper];
            pass_looper++;
        }
    }

    if(argc-optind != 2){
        fprintf(stderr,"Please pass the right arguments\n");
        fprintf (stderr, "Please Use \"./xcrypt -h\" for help\n");
        return 1;
    }
    keylen = strlen((char*)password);    
    infile = argv[optind];
    outfile = argv[optind+1];
    md = MD5(password, keylen ,res);
	printf("%ld\n",mycall(infile, outfile, (char*)md, strlen((char*)md), flags));	
	perror("");
	return 0;
}


/*--End of C file--*/
