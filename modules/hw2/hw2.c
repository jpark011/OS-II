#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define TO_OCTAT(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho_pre_route;
static struct nf_hook_ops nfho_post_route;
static struct nf_hook_ops nfho_forward;

static void setProtocol(char* str, unsigned int protocol) {
  switch (protocol) {
  case IPPROTO_ICMP:
    str = "ICMP";
    break;
  case IPPROTO_IGMP:
    str = "ICMP";
    break;

  case IPPROTO_TCP:
    str = "ICMP";
    break;

  case IPPROTO_UDP:
    str = "ICMP";
    break;

  default:
    str = "ERROR";
  }

  return;
}

unsigned int hw2_hook_fn(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct sk_buff *sock_buff;
    unsigned int saddr, daddr;
    unsigned int sport, dport;
    char proto[20];

    sock_buff = skb;

    // no header
    if (!sock_buff) {
      return NF_ACCEPT;
    }

    ip_header = (struct iphdr *)skb_network_header(sock_buff);

    // no IP header
    if (!ip_header) {
      return NF_ACCEPT;
    }

    // not TCP
    if(ip_header->protocol!=IPPROTO_TCP) {
      return NF_ACCEPT;
    }

    setProtocol(proto, ip_header->protocol);

    saddr = (unsigned int)ip_header->s_addr;
    daddr = (unsigned int)ip_header->d_addr;

    tcp_header = tcp_hdr(sock_buff);
    sport = htons((unsigned short int) tcp_header->source);
    dport = htons((unsigned short int) tcp_header->dest);

    // action depending on hook pos
    switch (hooknum) {
    // forwarding
    case NF_INET_PRE_ROUTING:
      printk(KERN_INFO "POST_ROUTING[%s;%d;%d;%d.%d.%d.%d;%d.%d.%d.%d]\n",
        proto, sport, dport, TO_OCTAT(saddr), TO_OCTAT(daddr));
      if (dport == 33333) {
        tcp_header->dest = 7777;
      }
      break;

    // monitoring
    case NF_INET_POST_ROUTING:
      printk(KERN_INFO "POST_ROUTING[%s;%d;%d;%d.%d.%d.%d;%d.%d.%d.%d]\n",
        proto, sport, dport, TO_OCTAT(saddr), TO_OCTAT(daddr));
      break;

    // monitoring
    case NF_INET_FORWARD:
      printk(KERN_INFO "POST_ROUTING[%s;%d;%d;%d.%d.%d.%d;%d.%d.%d.%d]\n",
        proto, sport, dport, TO_OCTAT(saddr), TO_OCTAT(daddr));
      break;

    default:
      break;
    }
    printk(KERN_INFO "TCP ports: source: %d, dest: %d \n", sport, dport);
    printk(KERN_INFO "SKBuffer: len %d, data_len %d\n", sock_buff->len, sock_buff->data_len);

    return NF_ACCEPT;
}

static int __init hw2_init(void) {
    // PRE_ROUNTING HOOK
    nfho_pre_route.hook = hw2_hook_fn;
    nfho_pre_route.hooknum = NF_INET_PRE_ROUTING;
    nfho_pre_route.pf = PF_INET;
    nfho_pre_route.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_pre_route);

    // POST_ROUTING HOOK
    nfho_post_route.hook = hw2_hook_fn;
    nfho_post_route.hooknum = NF_INET_POST_ROUTING;
    nfho_post_route.pf = PF_INET;
    nfho_post_route.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_post_route);

    // FORWARD HOOK
    nfho_forward.hook = hw2_hook_fn;
    nfho_forward.hooknum = NF_INET_FORWARD;
    nfho_forward.pf = PF_INET;
    nfho_forward.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_forward);

    return 0;
}

static void __exit hw2_exit(void) {
    nf_unregister_hook(&nfho_pre_route);
    nf_unregister_hook(&nfho_post_route);
    nf_unregister_hook(&nfho_forward);
}

module_init(hw2_init);
module_exit(hw2_exit);
