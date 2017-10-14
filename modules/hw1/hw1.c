#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>

#define PROC_DIRNAME "hw1"
#define PROC_FILENAME "hw1"

static struct proc_dir_entry *proc_dir;
static struct proc_dir_entry *proc_file;

extern unsigned long long hw1_block_number[2000];
extern long long int hw1_time[2000];
extern int hw1_index;
extern const char* hw1_file_system_name[2000];


static int hw1_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "hw1_open!\n");
    return 0;
}


static ssize_t hw1_write(struct file *file, const char __user *user_buffer, size_t count, loff_t *ppos) {
    int i;
    struct file *filp;
    char tmp[19];  
    
	
    mm_segment_t old_fs = get_fs();
    set_fs(KERNEL_DS);
    

    filp = filp_open("/tmp/result.csv", O_WRONLY|O_CREAT, 0644);
    if(IS_ERR(filp)) {
        printk("file open error\n");
	    set_fs(old_fs);
	
	    return count;
    }
    else {
        printk("file open success\n");
    }

    
    printk(KERN_INFO " hw1_write!\n");


    for(i = 0; i < 1000; i++) {
		
		if(hw1_file_system_name[i])
		if(user_buffer)
		if(strncmp(hw1_file_system_name[i], user_buffer, count-1) == 0)
		if(hw1_block_number[i]!=0) {
			
			snprintf(tmp, 19, "%lld", hw1_time[i]);
			
			vfs_write(filp, tmp, strlen(tmp), &filp->f_pos);
			vfs_write(filp, ", ", 2, &filp->f_pos);
	        
			
			snprintf(tmp, 19, "%lld", hw1_block_number[i]);
			
			
			vfs_write(filp, tmp, strlen(tmp), &filp->f_pos);
			vfs_write(filp, ", ", 2, &filp->f_pos);
			
			
			snprintf(tmp, 19, "%s", hw1_file_system_name[i]);
			vfs_write(filp, tmp, strlen(tmp), &filp->f_pos);
			vfs_write(filp, "\n", 1, &filp->f_pos);

			hw1_time[i]=0;
			hw1_block_number[i]=0;
			hw1_file_system_name[i]=NULL;
		}
   }

    printk(KERN_INFO "hw1_write complete.\n");

    filp_close(filp, NULL);

    set_fs(old_fs);



    return count;
}

static const struct file_operations hw1_proc_fops = {
    .owner = THIS_MODULE,
    .open = hw1_open,
    .write = hw1_write,
};

static int __init hw1_init(void) {
    printk(KERN_INFO "hw1 module Init\n");
    proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
    proc_file = proc_create(PROC_FILENAME, 0600, proc_dir, &hw1_proc_fops);
    return 0;
}

static void __exit hw1_exit(void) {
    printk(KERN_INFO "hw1 module Exit\n");

    return;
}

module_init(hw1_init);
module_exit(hw1_exit);

MODULE_AUTHOR("KU");
MODULE_DESCRIPTION("System_Programming_hw1");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
