#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KU");
MODULE_DESCRIPTION("System_Programming_hw2");
MODULE_VERSION("NEW");

#define TO_OCTAT(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho2;
static struct nf_hook_ops nfho3;
struct sk_buff *sock_buff;

unsigned int
hookfn(const struct nf_hook_ops *ops, struct sk_buff *skb,
       const struct net_device *in, const struct net_device *out,
       int (*okfn) (struct sk_buff *))
{
    uint8_t proto;
    struct ethhdr *eth;
	struct iphdr *ipv4h;
	struct tcphdr *tcp_h;
	unsigned int saddr, daddr;
	unsigned int sport, dport;
	unsigned char temp[4] = {100, 1, 1, 0};
	unsigned int tmp_addr;

	if (!skb)
		return NF_ACCEPT;


    eth = (struct ethhdr *)skb_mac_header(skb);
    if(ETH_P_IP == ntohs(eth->h_proto))
    {
	    ipv4h = (struct iphdr *) skb_network_header(skb);
		proto = ipv4h->protocol;
		saddr = (unsigned int)ipv4h->saddr;
    	daddr = (unsigned int)ipv4h->daddr;
        if(proto == IPPROTO_TCP){
			tcp_h = tcp_hdr(skb);
			sport = htons((unsigned short int) tcp_h->source);
			if(sport == 33333){
				memcpy(&tmp_addr, temp, sizeof(temp));
				ipv4h->daddr = tmp_addr;
				tcp_h->source = ntohs(7777);
				tcp_h->dest = ntohs(7777);
			}
			daddr = (unsigned int)ipv4h->daddr;
			sport = htons((unsigned short int) tcp_h->source);
		    dport = htons((unsigned short int) tcp_h->dest);
			printk("PRE_ROUTING[IPPROTO_TCP;%u;%u;%u.%u.%u.%u;%u.%u.%u.%u]\n",
       			 sport, dport, TO_OCTAT(saddr), TO_OCTAT(daddr));
			
		}
    }

	return NF_ACCEPT;
}

unsigned int
hookfn2(const struct nf_hook_ops *ops, struct sk_buff *skb,
       const struct net_device *in, const struct net_device *out,
       int (*okfn) (struct sk_buff *))
{
    uint8_t proto;
    struct ethhdr *eth;
	struct iphdr *ipv4h;
	struct tcphdr *tcp_h;
	unsigned int saddr, daddr;
	unsigned int sport, dport;

	if (!skb)
		return NF_ACCEPT;


    eth = (struct ethhdr *)skb_mac_header(skb);
    if(ETH_P_IP == ntohs(eth->h_proto))
    {
	    ipv4h = (struct iphdr *) skb_network_header(skb);
		proto = ipv4h->protocol;
		saddr = (unsigned int)ipv4h->saddr;
    	daddr = (unsigned int)ipv4h->daddr;
        if(proto == IPPROTO_TCP){
			tcp_h = tcp_hdr(skb);
			sport = htons((unsigned short int) tcp_h->source);
		    dport = htons((unsigned short int) tcp_h->dest);
			printk("FOWRAD[IPPROTO_TCP;%u;%u;%u.%u.%u.%u;%u.%u.%u.%u]\n",
       			 sport, dport, TO_OCTAT(saddr), TO_OCTAT(daddr));
		}
    }

	return NF_ACCEPT;
}


unsigned int
hookfn3(const struct nf_hook_ops *ops, struct sk_buff *skb,
       const struct net_device *in, const struct net_device *out,
       int (*okfn) (struct sk_buff *))
{
    uint8_t proto;
    struct ethhdr *eth;
	struct iphdr *ipv4h;
	struct tcphdr *tcp_h;
	unsigned int saddr, daddr;
	unsigned int sport, dport;

	if (!skb)
		return NF_ACCEPT;


    eth = (struct ethhdr *)skb_mac_header(skb);
    if(ETH_P_IP == ntohs(eth->h_proto))
    {
	    ipv4h = (struct iphdr *) skb_network_header(skb);
		proto = ipv4h->protocol;
		saddr = (unsigned int)ipv4h->saddr;
    	daddr = (unsigned int)ipv4h->daddr;
        if(proto == IPPROTO_TCP){
			tcp_h = tcp_hdr(skb);
			sport = htons((unsigned short int) tcp_h->source);
		    dport = htons((unsigned short int) tcp_h->dest);
			printk("POST_ROUTING[IPPROTO_TCP;%u;%u;%u.%u.%u.%u;%u.%u.%u.%u]\n",
       			 sport, dport, TO_OCTAT(saddr), TO_OCTAT(daddr));
		}
    }

	return NF_ACCEPT;
}

static int __init hook_init(void)
{
	nfho.hook = hookfn;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfho);
	
	nfho2.hook = hookfn2;
	nfho2.hooknum = NF_INET_FORWARD;
	nfho2.pf = PF_INET;
	nfho2.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfho2);

	nfho3.hook = hookfn3;
	nfho3.hooknum = NF_INET_POST_ROUTING;
	nfho3.pf = PF_INET;
	nfho3.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&nfho3);

	return 0;
}

static void __exit hook_exit(void)
{
	nf_unregister_hook(&nfho);
	nf_unregister_hook(&nfho2);
	nf_unregister_hook(&nfho3);
}

module_init(hook_init);
module_exit(hook_exit);
