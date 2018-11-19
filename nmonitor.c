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

#ifndef __KERNEL__
#define __KERNEL__
#endif

MODULE_LICENSE("GPL v2");

struct nf_hook_ops nfhook_recv;
struct nf_hook_ops nfhook_send;
struct iphdr *ip_header;
struct udphdr *udp_header;
struct tcphdr *tcp_header;


unsigned int hook_recv_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state){
	
	unsigned short dest_port;

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
			/* print out the information in the header */
			pr_info("Pack received from: %pI4\nProtocol: TCP\nDestination port: %d\n", 
					&(ip_header->saddr), dest_port);
			break;
		/* UDP  */
		case IPPROTO_UDP:
			/* get udp header if the protocol of the pack is udp */
			udp_header = udp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(udp_header->dest);
			/* print out the information in the header */
			pr_info("Pack received from: %pI4\nProtocol: UDP\nDestination port: %d",
					&(ip_header->saddr), dest_port);
			break;
		/* Other protocol like ICMP, RAW, ESP, etc.  */
		default:
			pr_info("Pack received from: %pI4\nProtocol: other", &(ip_header->saddr));
			break;
	}
	/* let netfilter accept the incoming pack */
	return NF_ACCEPT;
}

unsigned int hook_send_fn(void *priv, 
		struct sk_buff *skb, 
		const struct nf_hook_state *state) {

	unsigned short dest_port;

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
			/* print out the information in the header */
			pr_info("Pack sent to: %pI4\nProtocol: TCP\nDestination port: %d\n", 
					&(ip_header->saddr), dest_port);
			break;
		/* UDP  */
		case IPPROTO_UDP:
			/* get udp header if the protocol of the pack is udp */
			udp_header = udp_hdr(skb);
			/* translate from network bits order to host bits order */
			dest_port = ntohs(udp_header->dest);
			/* print out the information in the header */
			pr_info("Pack sent to: %pI4\nProtocol: UDP\nDestination port: %d",
					&(ip_header->saddr), dest_port);
			break;
		/* Other protocol like ICMP, RAW, ESP, etc.  */
		default:
			pr_info("Pack sent to: %pI4\nProtocol: other", &(ip_header->saddr));
			break;
	}
	/* let netfilter accept the outgoing pack */
	return NF_ACCEPT;
}

int __init monitor_load(void){

	/* set hook option */
	nfhook_recv.hook = hook_recv_fn;
	nfhook_recv.hooknum = NF_INET_PRE_ROUTING;	// resigister pre routing hook
	nfhook_recv.pf = PF_INET;
	nfhook_recv.priority = 1;
	/* check if registration is successful */
	if (nf_register_net_hook(&init_net, &nfhook_recv)) {
		pr_err("Could not register the netfilter receiving hook");
	}
	
	nfhook_send.hook = hook_send_fn;
	nfhook_send.hooknum = NF_INET_POST_ROUTING;	// resigister pre routing hook
	nfhook_send.pf = PF_INET;
	nfhook_send.priority = 1;
	if (nf_register_net_hook(&init_net, &nfhook_send)) {
		pr_err("Could not register the netfilter receiving hook");
	}
	 
	return 0;
}

void __exit monitor_exit(void){
	
	/* unresigter hook when exiting the module */
	nf_unregister_net_hook(&init_net, &nfhook_recv);
	nf_unregister_net_hook(&init_net, &nfhook_send);
	return;
}

module_init(monitor_load);
module_exit(monitor_exit);


