#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <asm/unistd.h>

#ifndef __KERNEL__
#define __KERNEL__
#endif

MODULE_LICENSE("GPL v2");

struct nf_hook_ops nfhook;
struct iphdr *ip_header;

unsigned int hook_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state){

	ip_header = ip_hdr(skb);	
	pr_info("Pack sent by: %pI4\n", &(ip_header->saddr));

	return NF_ACCEPT;
}

int __init monitor_load(void){

	nfhook.hook = hook_fn;
	nfhook.hooknum = NF_INET_PRE_ROUTING;
	nfhook.pf = PF_INET;
	nfhook.priority = 1;

	if (nf_register_net_hook(&init_net, &nfhook)) {
		pr_err("Could not register the netfilter hook");
	}

	return 0;
}

void __exit monitor_exit(void){
	
	nf_unregister_net_hook(&init_net, &nfhook);
	return;
}

module_init(monitor_load);
module_exit(monitor_exit);


