#include <linux/kernel.h>		// included for printk
#include <linux/module.h>		// required for all the LKM
#include <linux/init.h>			// included for __init and __exit
#include <linux/netfilter.h>	// included for netfilter functionality
#include <linux/ip.h>			// included for ip_hdr
#include <linux/tcp.h>			// included for tcp_hdr
#include <linux/udp.h>			// included for udp_hdr
#include <linux/types.h>		// included for typing less words
#include <linux/inet.h>			// included for in_aton
#include <linux/moduleparam.h>	// included for module_param

/*********************************************/
/* declartion of varibles and function below */
/*********************************************/

/* hook options stuct for both receiving and sending */
struct nf_hook_ops nfhook_recv;
struct nf_hook_ops nfhook_send;

/* differnet types of headers for different layers and protocols */
struct iphdr *ip_header;
struct udphdr *udp_header;
struct tcphdr *tcp_header;

/* module parameters needed */
/* option for blacklist mode or whitelist mode, 0 for blacklist and 1 for 
 * whitelist */
static int mode;

/* an string array of ip addresses */
static char* addr[100];
static int count_addr;

/* an unsigned short array of port numbers */
static unsigned short port[100];
static int count_port;

/**
 * Check if the ip address and port number should be blocked according to 
 * user's configuration in the file /etc/modprobe.d/nmonitor.conf.
 *
 * @ip_addr: the ip address of the pack, source address for pack received and 
 * 				destination address for pack sending out
 * @p: the port number of the pack
 *
 * Return true 	- the @ip_addr and @p are in the list and mode is 0 
 * 				- the @ip_addr and @p are not in the list and mode is 1	
 * 	      false - the @ip_addr and @p are in the list and mode is 1
 * 				- the @ip_addr and @p are not in the list and mode is 0
 */
bool is_blocked(__be32 ip_addr, unsigned short p);

/**
 * Check if the pack should be accepted or dropped according to the result 
 * checked by the function is_blocked. This function that will be 
 * triggered when pack arrived.
 * 
 * @priv: a pointer to the privilge of the hook triggered? Not clear, not used 
 * 			in this module
 * @skb: a pointer to the network packet buffer
 * @state: a pointer to the struct contains the state information of the hook
 * 	       	triggered
 *
 * Return NF_ACCEPT if the pack in @skb should not be blocked and NF_DROP if 
 * it should be, which allows netfilter to accept the pack or drop the pack.
 */
unsigned int hook_recv_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state);

/**
 * Check if the pack should be accepted or dropped according to the result 
 * checked by the function is_blocked. This function that will be 
 * triggered when pack is about to be sent.
 *
 * @priv: a pointer to the privilge of the hook triggered? Not clear, not used 
 * 			in this module
 * @skb: a pointer to the network packet buffer
 * @state: a pointer to the struct contains the state information of the hook
 * 	       	triggered
 *
 * Return NF_ACCEPT if the pack in @skb should not be blocked and NF_DROP if 
 * it should be, which allows netfileter to accept the pack or drop it.
 */
unsigned int hook_send_fn(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state);

int __init monitor_load(void);

void __exit monitor_exit(void);

