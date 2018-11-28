#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <asm/unistd.h>
#include <linux/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/inet.h>
#include <linux/moduleparam.h>

#ifndef __KERNEL__
#define __KERNEL__
#endif

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Roy Huang, Zhiyuan Zhao");
MODULE_DESCRIPTION("An network monitor and filter LKM");


/* hook options stuct for both receiving and sending */
struct nf_hook_ops nfhook_recv;
struct nf_hook_ops nfhook_send;

struct iphdr *ip_header;
struct udphdr *udp_header;
struct tcphdr *tcp_header;

/* module parameters needed */
static int mode;
static char* addr[100];
static int count_addr;
static unsigned short port[100];
static int count_port;

/* get parameters values from options */
module_param(mode, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(mode, "option for blacklist mode or whitelist mode, 0 for "
		"blacklist and 1 for whitelist");

module_param_array(addr, charp, &count_addr, 0644);
MODULE_PARM_DESC(addr, "an string array of ip addresses");

module_param_array(port, ushort, &count_port, 0644);
MODULE_PARM_DESC(port, "an unsigned short array of port number");

/**
 * Check if the ip address and port number should be blocked according to 
 * user's configuration in the file /etc/modprobe.d/nmonitor.conf.
 *
 * @ip_addr: the ip address of the pack, source address for pack received and 
 * 				destination address for pack sending out.
 * @p: the port number of the pack
 *
 * Return true 	- the @ip_addr and @p are in the list and mode is 0 
 * 				- the @ip_addr and @p are not in the list and mode is 1	
 * 	      false - the @ip_addr and @p are in the list and mode is 1
 * 				- the @ip_addr and @p are not in the list and mode is 0
 */
bool is_blocked(__be32 ip_addr, unsigned short p) {
	bool in_list;
	bool blocked;
	int i;
	int j;
	__be32 blocked_ip;
	unsigned short blocked_port;

	in_list = false;

	/* iterate through the ip addresses list from the configuration file */
	i = 0;
	while (!in_list && i < count_addr) {
		blocked_ip = in_aton(addr[i]);
		in_list = (ip_addr == blocked_ip);
		i++;
	}
	
	/* iterate through the ports list from the configuration file */
	j = 0;
	while (!in_list && j < count_port) {
		blocked_port = port[j];
		in_list = (p == blocked_port);
		j++;
	}
	
	/* different results for different mode 
	 * could use expression like blocked = in_list && mode, but for easier 
	 * readability, chose use if-else statement 
	 */
	if (mode == 0) {		// blacklist
		if (in_list){
			blocked = true;
		} else {
			blocked = false;
		}
	} else {		// whitelist
		if (in_list) {
			blocked = false;
		} else {
			blocked = true;
		}
	}

	return blocked;
}

unsigned int hook_recv_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state){

	unsigned short dest_port;

	/* hard coding for demo purpose */
	/* get ip header from socket buffer we are owned */
	ip_header = ip_hdr(skb);

	/* get different header for different protocol  */
	switch (ip_header->protocol) {
		/* TCP */
		case IPPROTO_TCP:
			/* get tcp header if the protocol of the pack is tcp */
			tcp_header = tcp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(tcp_header->dest);

			if (is_blocked(ip_header->saddr, dest_port)) {
				pr_info("----------------------------------------------------\n"
						"Dropped pack received from: %pI4\n"
						"Protocol: TCP\nDestination port: %d\n", 
						&(ip_header->saddr), dest_port);
				return NF_DROP;
			}

			/* print out the information in the header */
			pr_info("----------------------------------------------------\n"
					"Pack received from: %pI4\n"
					"Protocol: TCP\nDestination port: %d\n", 
					&(ip_header->saddr), dest_port);
			break;

		/* UDP */
		case IPPROTO_UDP:
			/* get udp header if the protocol of the pack is udp */
			udp_header = udp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(udp_header->dest);

			if (is_blocked(ip_header->saddr, dest_port)) {
				pr_info("----------------------------------------------------\n"
						"Dropped pack received from: %pI4\n"
						"Protocol: UDP\nDestination port: %d\n", 
						&(ip_header->saddr), dest_port);
				return NF_DROP;
			}

			/* print out the information in the header */
			pr_info("----------------------------------------------------\n"
					"Pack received from: %pI4\n"
					"Protocol: UDP\nDestination port: %d",
					&(ip_header->saddr), dest_port);
			break;

		/* Other protocol like ICMP, RAW, ESP, etc. */
		default:
			pr_info("----------------------------------------------------\n"
					"Pack received from: %pI4\n"
					"Protocol: other", &(ip_header->saddr));
			break;
	}
	/* let netfilter accept the incoming pack */
	return NF_ACCEPT;
}

unsigned int hook_send_fn(void *priv, 
		struct sk_buff *skb, 
		const struct nf_hook_state *state) {

	unsigned short dest_port;

	/* hard coding for demo purpose */
	/* get ip header from socket buffer we are owned */
	ip_header = ip_hdr(skb);

	/* get different header for different protocol  */
	switch (ip_header->protocol) {
		/* TCP */
		case IPPROTO_TCP:
			/* get tcp header if the protocol of the pack is tcp */
			tcp_header = tcp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(tcp_header->dest);

			if (is_blocked(ip_header->daddr, dest_port)) {
				pr_info("----------------------------------------------------\n"
						"Dropped pack sending to: %pI4\n"
						"Protocol: TCP\nDestination port: %d\n", 
						&(ip_header->daddr), dest_port);
				return NF_DROP;
			}

			/* print out the information in the header */
			pr_info("----------------------------------------------------\n"
					"Pack sent to: %pI4\n"
					"Protocol: TCP\nDestination port: %d\n", 
					&(ip_header->saddr), dest_port);
			break;

		/* UDP */
		case IPPROTO_UDP:
			/* get udp header if the protocol of the pack is udp */
			udp_header = udp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(udp_header->dest);

			if (is_blocked(ip_header->daddr, dest_port)) {
				pr_info("----------------------------------------------------\n"
						"Dropped pack sending to: %pI4\n"
						"Protocol: UDP\nDestination port: %d\n", 
						&(ip_header->daddr), dest_port);
				return NF_DROP;
			}

			/* print out the information in the header */
			pr_info("----------------------------------------------------\n"
					"Pack sent to: %pI4\n"
					"Protocol: UDP\nDestination port: %d",
					&(ip_header->daddr), dest_port);
			break;

		/* Other protocol like ICMP, RAW, ESP, etc. */
		default:
			pr_info("----------------------------------------------------\n"
					"Pack sent to %pI4\n"
					"Protocol: other", &(ip_header->saddr));
			break;
	}
	/* let netfilter accept the incoming pack */
	return NF_ACCEPT;
}

/* module initialization function */
int __init monitor_load(void){

	if (mode == 0) {
		pr_info("Mode: Blacklist");
	} else {
		pr_info("Mode: Whitelist");
	}

	/* set hook option for pre routing */
	nfhook_recv.hook = hook_recv_fn;
	nfhook_recv.hooknum = NF_INET_PRE_ROUTING;	// resigister pre routing hook
	nfhook_recv.pf = PF_INET;
	nfhook_recv.priority = 1;
	/* check if registration is successful */
	if (nf_register_net_hook(&init_net, &nfhook_recv)) {
		pr_err("Could not register the netfilter receiving hook");
	}

	/* set hook option for post routing */
	nfhook_send.hook = hook_send_fn;
	nfhook_send.hooknum = NF_INET_POST_ROUTING;	// resigister porst routing hook
	nfhook_send.pf = PF_INET;
	nfhook_send.priority = 1;
	if (nf_register_net_hook(&init_net, &nfhook_send)) {
		pr_err("Could not register the netfilter receiving hook");
	}

	return 0;
}

/* module exit function */
void __exit monitor_exit(void){

	/* unresigter hook when exiting the module */
	nf_unregister_net_hook(&init_net, &nfhook_recv);
	nf_unregister_net_hook(&init_net, &nfhook_send);
	return;
}

module_init(monitor_load);
module_exit(monitor_exit);

