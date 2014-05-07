/* 
 * sys_xcrypt.c - This is the function module that is being implemented. 
 * The Function Load Mod is called when the system call sys_xcrpyt()  
 * is made.
 * (Sorry for the duplication of names (actual system call and the module have the same name))
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/namei.h>
#include <linux/stat.h>
#include <linux/path.h>
#include <linux/err.h>
#include <crypto/hash.h>
#define PAD 16
#define HASHLEN 16
#define AES_KEY_SIZE 16

#define BLOCK_READ_SIZE PAGE_SIZE
#define ENCRYPT 1
#define DECRYPT 0
#define TASK_MASK 0x0001

#define ERR printk("KERN_ERR [%d]%s: %s\n", __LINE__, __FILE__, __func__)
#define DEBUGINT(value) printk("KERN_INFO [%d]%s: %s : [%d]\n", __LINE__, __FILE__, __func__, value)
#define DEBUGUINT(value) printk("KERN_INFO [%ld]%s: %s : [%d]\n", __LINE__, __FILE__, __func__, value)
#define DEBUG(msg) printk("KERN_INFO [%d]%s: %s : [%s]\n", __LINE__, __FILE__, __func__, msg)

static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void){
    return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}
const u8 *aes_iv = "cephsageyudagreg";
extern int (*function_pointer)(char*, char*, char*, int, int);

/*
Description: Gets the stat structure of the file
@param fname: Name of the File
@param fstat: Pointer to instance of struct stat
@return 0 in success, -1 with errno being set on error
REFERENCE
http://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c-cross-platform
http://linux.die.net/man/2/stat
*/
int file_stat(char* fname, struct kstat *fstat){
    int stat_val;
    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(KERNEL_DS);
    stat_val = vfs_stat(fname,fstat);
    set_fs(old_fs);
    return stat_val;
}

/*
Description: Gets the stat structure of the file
@param fname_in: Name of the input file
@param fname_out: Name of output file
@return 0 on success, a non zero value otherwise
REFERENCE
http://www.win.tue.nl/~aeb/linux/lk/lk-8.html
*/
int if_same_file(char* fname_in,char* fname_out){
    struct path in, out;
    int ret_val = 0;

    mm_segment_t old_fs;
    old_fs = get_fs();
    set_fs(KERNEL_DS);

    ret_val = kern_path(fname_in,LOOKUP_FOLLOW,&in);
    if(ret_val != 0){
        ERR;
        goto EXIT_if_same_file;
    }
    ret_val = kern_path(fname_out,LOOKUP_FOLLOW,&out);
    if(ret_val != 0 && ret_val != -ENOENT){
        ERR;
        goto EXIT_if_same_file;
    }
   if((strcmp(in.dentry->d_inode->i_sb->s_id, out.dentry->d_inode->i_sb->s_id) == 0)
       && (in.dentry->d_inode->i_ino == out.dentry->d_inode->i_ino)){
       ret_val = 1;
       ERR;
       goto EXIT_if_same_file;
    }
    ret_val = 0;
EXIT_if_same_file:
    set_fs(old_fs);
    return ret_val;
}

int kernel_hash(char* key, int keylen, char* output_buf){
    int ret_val = 0;
    struct scatterlist sg[1];
    struct hash_desc desc;

    struct crypto_hash *tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
    if (!tfm || IS_ERR(tfm)){
        ret_val = (int)PTR_ERR(tfm);
        ERR;
        goto EXIT_kernel_hash;
    }      
    
    desc.tfm = tfm;
    ret_val = crypto_hash_init(&desc);
    if (ret_val != 0){
        ERR;
        goto EXIT_kernel_hash;
    }

    sg_init_table(sg, ARRAY_SIZE(sg));
    sg_set_buf(&sg[0], key, keylen);

    ret_val = crypto_hash_digest(&desc, sg, keylen, output_buf);
    if (ret_val != 0){
        ERR;
        goto EXIT_kernel_hash;
    }
    return ret_val;        

EXIT_kernel_hash:
    return ret_val;
}

/*
Description: Unlinks a file
@param fname: Name of the file to be unlinked
@param fd: File structure representing the open file
@return 0 on success, a non zero value otherwise wise
*/
int file_unlink(char* fname, struct file* fd){
    struct path file;
    int ret_val;
    mm_segment_t old_fs;
    
    filp_close(fd, NULL);

    old_fs = get_fs();
    set_fs(KERNEL_DS);

    ret_val = kern_path(fname, LOOKUP_FOLLOW, &file);
    if(ret_val != 0){
        ERR;
        goto EXIT_file_unlink;
    }

    ret_val = vfs_unlink(file.dentry->d_parent->d_inode, file.dentry);
    if(ret_val != 0){
        ERR;
        goto EXIT_file_unlink;
    }
    ret_val = 0;

EXIT_file_unlink:
    set_fs(old_fs);
    return(ret_val);
}
/* Description: CEPH_AES_ENCRYPT copied from net/ceph/crypto.c
 * @param key: Key for encryption
 * @param key_len: Length of the key
 * @param dst: Destination buffer to fill in encrypted data
 * @param dst_len: The length of the destination buffer
 * @param src: Source data that needs to be encrypted
 * @param src_len: Length of source data
 * return 0 on success, errno otherwise
*/
int ceph_aes_encrypt(const void *key, int key_len, void *dst, size_t *dst_len,
                      const void *src, size_t src_len){
    
    struct scatterlist sg_in[2], sg_out[1];
    struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
    struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
    int ret;
    void *iv;
    int ivsize;
    size_t zero_padding = (0x10 - (src_len & 0x0f));
    char pad[16];
    
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    
    memset(pad, zero_padding, zero_padding);
    
    *dst_len = src_len + zero_padding;
    crypto_blkcipher_setkey((void *)tfm, key, key_len);
    sg_init_table(sg_in, 2);
    sg_set_buf(&sg_in[0], src, src_len);
    sg_set_buf(&sg_in[1], pad, zero_padding);
    sg_init_table(sg_out, 1);
    sg_set_buf(sg_out, dst, *dst_len);
    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm); 
    memcpy(iv, aes_iv, ivsize);
    
    ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
                                      src_len + zero_padding);
    crypto_free_blkcipher(tfm);
    if (ret < 0)
        pr_err("ceph_aes_crypt failed %d\n", ret);

    return 0;
}

/* Description: CEPH_AES_DECRYPT copied from net/ceph/crypto.c
 * @param key: Key for decryption
 * @param key_len: Length of the key
 * @param dst: Destination buffer to fill in decrypted data
 * @param dst_len: The length of the destination buffer
 * @param src: Source data that needs to be decrypted
 * @param src_len: Length of source data
 * return 0 on success, errno otherwise
*/

int ceph_aes_decrypt(const void *key, int key_len, void *dst, size_t *dst_len,
                      const void *src, size_t src_len){
    struct scatterlist sg_in[1], sg_out[2];
    struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
    struct blkcipher_desc desc = { .tfm = tfm };
    char pad[16];
    void *iv;
    int ivsize;
    int ret;
    int last_byte;
    
    if (IS_ERR(tfm))
        return PTR_ERR(tfm);
    
    crypto_blkcipher_setkey((void *)tfm, key, key_len);
    sg_init_table(sg_in, 1);
    sg_init_table(sg_out, 2);
    sg_set_buf(sg_in, src, src_len);
    sg_set_buf(&sg_out[0], dst, *dst_len);
    sg_set_buf(&sg_out[1], pad, sizeof(pad));

    iv = crypto_blkcipher_crt(tfm)->iv;
    ivsize = crypto_blkcipher_ivsize(tfm);
    
    memcpy(iv, aes_iv, ivsize); 

    ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
    crypto_free_blkcipher(tfm);
    if (ret < 0) {
        pr_err("ceph_aes_decrypt failed %d\n", ret);
        return ret;
    }
         
    if (src_len <= *dst_len)
        last_byte = ((char *)dst)[src_len - 1];
    else
        last_byte = pad[src_len - *dst_len - 1];

    if (last_byte <= 16 && src_len >= last_byte) {
        *dst_len = src_len - last_byte;
    } 
    else {
        pr_err("ceph_aes_decrypt got bad padding %d on src len %d\n",
                    last_byte, (int)src_len);
        return -EPERM;  /* bad padding */
    }
    
    return 0;
}

int loadMod(char *infile, char* outfile, char *keybuf, int keylen, int flags){

    char* k_in = NULL; //FREE in the end
    char* k_out = NULL; //FREE in the end
    char* k_keybuf = NULL; //FREE in the end
    char* k_tempbuf = NULL; //FREE in the end
    char* k_tempdst = NULL; //FREE in the end
    size_t k_dstlen = 0;
    size_t k_buflen = 0;
    size_t read_bytes = 0;
    int return_val = 0;
    struct kstat in_stat,out_stat;
    struct file *in_fd = NULL;
    struct file *out_fd = NULL;

    int write_bytes = 0;

    mm_segment_t old_fs;

	//Check For Null Arguments
    //Check for pointers to bad address
    k_in = getname(infile); //EXIT_1
    if(!k_in || IS_ERR(k_in)){
        ERR;
        return_val = (int)PTR_ERR(k_in);
            goto EXIT;
    }
    

    k_out = getname(outfile); //EXIT_2
    if(!k_out || IS_ERR(k_out)){
        ERR;
        return_val = (int)PTR_ERR(k_out);
        goto EXIT_1;
    }


    /*Check if input file exists*/
    return_val = file_stat(k_in, &in_stat); 
    if(return_val < 0){
        ERR;
        goto EXIT_2;
    }

    /*Check if Output file exits*/
    return_val = file_stat(k_out, &out_stat);
    if(return_val < 0 && return_val != -ENOENT){
        ERR;
        goto EXIT_2;
    }
    else if(return_val == 0){
    /*If output file also exits, then check if its the same as the input file*/
        return_val = if_same_file(k_in, k_out);
        if(return_val == 1){
            ERR;
            return_val = -EINVAL;
            goto EXIT_2;
        }
        else if(return_val < 0){
            ERR;
            goto EXIT_2;
        }
    }
    else{
        return_val = 0;
    }

    k_keybuf = getname(keybuf); //EXIT_3
    if(!k_keybuf || IS_ERR(k_keybuf)){
        ERR;
        return_val = (int)PTR_ERR(k_keybuf);
        goto EXIT_2;
    }

    /*Checking if length of keybuf and key length dont match*/
    if(strlen(k_keybuf) != keylen){
        ERR;
        return_val = -EINVAL;
        goto EXIT_3;
    }
    
    in_fd = filp_open(k_in, O_RDONLY, 0);//EXIT_4
    if(!in_fd || IS_ERR(in_fd)){
        ERR;
        return_val = (int)PTR_ERR(in_fd);
        goto EXIT_3;
    }

    out_fd = filp_open(k_out, O_CREAT|O_WRONLY|O_TRUNC, in_stat.mode);//EXIT_5
    if(!out_fd || IS_ERR(out_fd)){
        ERR;
        return_val = (int)PTR_ERR(out_fd);
        goto EXIT_4;
    } 
    
    k_tempbuf = (char*)kmalloc(BLOCK_READ_SIZE+PAD, GFP_KERNEL);//EXIT_6
    if(!k_tempbuf || IS_ERR(k_tempbuf)){
        ERR;
        return_val = -ENOMEM;
        goto EXIT_5;
    }
    memset(k_tempbuf, 0, BLOCK_READ_SIZE+PAD);
    k_buflen = (size_t)BLOCK_READ_SIZE;
    

    k_tempdst = (char*)kmalloc(BLOCK_READ_SIZE+PAD, GFP_KERNEL);//EXIT_7
    if(!k_tempdst || IS_ERR(k_tempdst)){
        ERR;
        return_val = -ENOMEM;
        goto EXIT_6;
    }
    memset(k_tempdst, 0, BLOCK_READ_SIZE+PAD);
    k_dstlen = (size_t)BLOCK_READ_SIZE;
    
    flags = flags & TASK_MASK;
    
    old_fs = get_fs(); //EXIT_7
    set_fs(KERNEL_DS);

    if(flags == ENCRYPT){
        in_fd->f_pos = 0;
        out_fd->f_pos = 0;
        memset(k_tempbuf, 0, BLOCK_READ_SIZE+PAD);
        memset(k_tempdst, 0, BLOCK_READ_SIZE+PAD);
        
        return_val = kernel_hash(k_keybuf, keylen, k_tempdst);
        if(return_val != 0){
            ERR;
            file_unlink(k_out, out_fd);
            goto EXIT_7;
        }
        print_hex_dump_bytes("KERNEL HASH: ", DUMP_PREFIX_NONE, k_tempdst, 16);

        /* Writing the preamble of 16 bytes*/
        write_bytes = vfs_write(out_fd, k_tempdst, HASHLEN, &(out_fd->f_pos));
        if(write_bytes < 0){
                    ERR;
                    return_val = -EFAULT;
                    file_unlink(k_out, out_fd);
                    goto EXIT_7;
        }
        /*Writing to the file*/
        while(true){
            memset(k_tempbuf, 0, BLOCK_READ_SIZE+PAD);
            memset(k_tempdst, 0, BLOCK_READ_SIZE+PAD);
            read_bytes = vfs_read(in_fd, k_tempbuf, BLOCK_READ_SIZE, &(in_fd->f_pos));
            if(read_bytes < 0){
                ERR;
                return_val = -EFAULT;
                file_unlink(k_out, out_fd);
                goto EXIT_7;
            }
            else if(read_bytes == 0){
                break;
            }
            else{
                k_dstlen = read_bytes;
                return_val = ceph_aes_encrypt(k_keybuf, keylen, k_tempdst, &k_dstlen, k_tempbuf, read_bytes); 
                if(return_val != 0){
                    ERR;
                    file_unlink(k_out, out_fd);
                    goto EXIT_7;
                }
                write_bytes = vfs_write(out_fd, k_tempdst, k_dstlen, &(out_fd->f_pos));
                if(write_bytes < 0){
                    ERR;
                    return_val = -EFAULT;
                    file_unlink(k_out, out_fd);
                    goto EXIT_7;
                }
            }
        }
    }
    if(flags == DECRYPT){
        
        in_fd->f_pos = 0;
        out_fd->f_pos = 0;
        
        memset(k_tempbuf, 0, BLOCK_READ_SIZE+PAD);
        memset(k_tempdst, 0, BLOCK_READ_SIZE+PAD);
        /*Hashing the key from the user*/
        return_val = kernel_hash(k_keybuf, keylen, k_tempdst);
        if(return_val != 0){
            ERR;
            file_unlink(k_out, out_fd);
            goto EXIT_7;
        }
        print_hex_dump_bytes("KERNEL HASH: ", DUMP_PREFIX_NONE, k_tempdst, HASHLEN);
        /* Reading the preamble */
        read_bytes = vfs_read(in_fd, k_tempbuf, HASHLEN, &(in_fd->f_pos));
         if(read_bytes < 0){
                ERR;
                return_val = -EFAULT;
                file_unlink(k_out, out_fd);
                goto EXIT_7;
            }
        /* Comparing the preamble to the hash obtained */
        return_val = memcmp(k_tempbuf, k_tempdst, HASHLEN);
        if(return_val != 0){
            ERR;
            return_val = -EACCES;
            file_unlink(k_out, out_fd);
            goto EXIT_7;
        }
        /* Decrypting the file if the hash and the preamble match */    
        while(true){
            memset(k_tempbuf, 0, BLOCK_READ_SIZE+PAD);
            memset(k_tempdst, 0, BLOCK_READ_SIZE+PAD);

            read_bytes = vfs_read(in_fd, k_tempbuf, BLOCK_READ_SIZE+16, &(in_fd->f_pos));
            if(read_bytes < 0){
                ERR;
                return_val = -EFAULT;
                file_unlink(k_out, out_fd);
                goto EXIT_7;
            }
            else if(read_bytes == 0){
                break;
            }
            else{
                k_dstlen = read_bytes;
                return_val = ceph_aes_decrypt(k_keybuf, keylen, k_tempdst, &k_dstlen, k_tempbuf, read_bytes);
                if(return_val != 0){
                    ERR;
                    file_unlink(k_out, out_fd);
                    goto EXIT_7;
                }
                write_bytes = vfs_write(out_fd, k_tempdst, k_dstlen, &(out_fd->f_pos));
                if(write_bytes < 0){
                    ERR;
                    return_val = -EFAULT;
                    file_unlink(k_out, out_fd);
                    goto EXIT_7;
                }
            }
        }
    }
   

EXIT_7:
    set_fs(old_fs);
    kfree(k_tempdst);
    k_tempdst = NULL;
EXIT_6:
    kfree(k_tempbuf);
    k_tempbuf = NULL;
EXIT_5:
    filp_close(out_fd, NULL);
EXIT_4:
    filp_close(in_fd, NULL);
EXIT_3:
    putname(k_keybuf);
    k_keybuf = NULL;
EXIT_2:
    putname(k_out);
    k_out = NULL;
EXIT_1:
    putname(k_in);
    k_in = NULL;
EXIT:
    return(return_val);
}

static int __init hello_init(void){
	printk(KERN_INFO "INSIDE INIT\n");
	function_pointer = loadMod;
	return 0;
}

static void __exit hello_exit(void){
	printk(KERN_INFO "INSIDE_EXIT\n");
	if(function_pointer == loadMod){
		function_pointer = NULL;
	}
	else{
	}
}

module_init(hello_init);
module_exit(hello_exit);


MODULE_LICENSE("GPL");
