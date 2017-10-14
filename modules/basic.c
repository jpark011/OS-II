#include <linux/module.h>    // included for all kernel modules
// #include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros


static int __init hello_init(void)
{
    printk(KERN_ALERT "Hello world!\n");
    return 0;    // Non-zero return means that the module couldn't be loaded.
}

static void __exit hello_exit(void)
{
    printk(KERN_ALERT "Goodbye, world.\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_AUTHOR("Korea University");
MODULE_DESCRIPTION("A Simple Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
