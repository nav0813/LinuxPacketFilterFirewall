#include "netfltrHooks.h"

/* struct to store the rules*/
struct t_rule {
	char pkt; // 0 - outgoing, 1- incoming, 2 - error
	char block; // 0 - unblock, 1 - block, 2 - error
	unsigned int srcip; // source ip address
	unsigned int dstip; // destination ip address
	unsigned int srcpt; //source port number
	unsigned int dstpt; //destination port number
	char proto; // 0 - all, 1 - tcp, 2 - udp, 3 - error
};


extern int ruleCount;
extern struct t_rule T_RULES[];

static struct sk_buff* sock_buff;
static struct udphdr* udp_header; //udp header struct (not used)
static struct iphdr* ip_header; //ip header struct
static struct tcphdr* tcp_header; //tcp header struct


/**
 * Netfilter hook function for incoming packets
 *  
 */
unsigned int in_hook_func(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, 
		const struct net_device* out, int (*okfn)(struct sk_buff* ))
{
	int i;	
	sock_buff = skb;

	/* Extract network header using accessor */
	ip_header = (struct iphdr* )skb_network_header(sock_buff);  
	udp_header = (struct udphdr* )skb_transport_header(sock_buff);
	tcp_header = (struct udphdr* )skb_transport_header(sock_buff); 
       
    if(!sock_buff) { return NF_ACCEPT;}
	/* Iterate through the T_RULES array */
	for(i=0;i<ruleCount;i++) {
		/* Check if the rule is for incoming packets */
		if(T_RULES[i].pkt == 1) {
			/* Check if the rule has protocol field set to ALL */
			if(T_RULES[i].proto == 0 ) {
				/* Check IP address */
				if(compare_ip((unsigned int)ip_header->saddr, T_RULES[i].srcip)) {
					/* Check destination port number */
					if(compare_port(tcp_header->dest, T_RULES[i].dstpt)) {
						/* Check whether to BLOCK the packet */
						if(T_RULES[i].block == 1) {
							printk(KERN_INFO"firewall: Blocking incoming pkts\n");
							return NF_DROP;
						} else {
							if(T_RULES[i].block == 0) {
								printk(KERN_INFO"firewall: Unblocking incoming pkts");
								return NF_ACCEPT;
							}
						}
					}	
				}
			} 
			/* Check if the rule has protocol field set to TCP */
			if((T_RULES[i].proto == 1) && (ip_header->protocol == 6)){
				/* Check IP address */
				if(compare_ip((unsigned int)ip_header->saddr, T_RULES[i].srcip)) {
					/* Check destination port number */
					if(compare_port(tcp_header->dest, T_RULES[i].dstpt)) {
						/* Check whether to BLOCK the packet */
						if(T_RULES[i].block == 1) {							
							printk(KERN_INFO"firewall: Blocking Incoming TCP pkts\n");
							return NF_DROP;
						} else {
							if(T_RULES[i].block == 0) {
								printk(KERN_INFO"firewall: Unblocking Incoming TCP pkts");
								return NF_ACCEPT;
							}
						}
					}
				}
			}
			/* Check if the rule has protocol field set to UDP */
			if((T_RULES[i].proto == 2) && (ip_header->protocol == 17)) {
				/* Check IP address */
				if(compare_ip((unsigned int)ip_header->saddr, T_RULES[i].srcip)) {
					/* Check destination port number */
					if(compare_port(tcp_header->dest, T_RULES[i].dstpt)) {
						/* Check whether to BLOCK the packet */
						if(T_RULES[i].block == 1) {
							printk(KERN_INFO"firewall: Blocking Incoming UDP pkts\n");
							return NF_DROP;
						} else {
							if(T_RULES[i].block == 0) {
								printk(KERN_INFO"firewall: Unblocking all Incoming UDP pkts");
								return NF_ACCEPT;
							}
						}		
					}
				} 	
			}	
		}

	}
	return NF_ACCEPT;
}

/**
 * Netfilter hook function for outgoing packets
 *  
 */
unsigned int out_hook_func(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, 
		const struct net_device* out, int (*okfn)(struct sk_buff* ))
{
	int i;
	sock_buff = skb;
 
	/* Extract network header using accessor */
    ip_header = (struct iphdr* )skb_network_header(sock_buff);   
    tcp_header = (struct udphdr* )skb_transport_header(sock_buff);
    
    if(!sock_buff) { return NF_ACCEPT;}

    /* Iterate through the T_RULES array */
	for(i=0;i<ruleCount;i++) {
		/* Check if the rule is for incoming packets */
		if(T_RULES[i].pkt == 0) {
			/* Check if the rule has protocol field set to ALL */
			if(T_RULES[i].proto == 0) {
				/* Check IP address */
				if( compare_ip((unsigned int)ip_header->daddr, T_RULES[i].srcip)) {
					/* Check port number */
					if(compare_port(tcp_header->dest, T_RULES[i].dstpt)) {
						/* Check whether to BLOCK the packet */
						if(T_RULES[i].block == 1) {
							printk(KERN_INFO"firewall: Blocking all outgoing pkts\n");
							return NF_DROP;
						} else {
							if(T_RULES[i].block == 0) {
								printk(KERN_INFO"firewall: Unblocking all outgoing pkts");
								return NF_ACCEPT;
							}
						}
					}
				}
			} 
			/* Check if the rule has protocol field set to TCP */
			if((T_RULES[i].proto == 1) && (ip_header->protocol == 6)) {
				/* Check IP address */
				if(compare_ip((unsigned int)ip_header->daddr, T_RULES[i].srcip)) {
					/* Check the port numbers */
					if(compare_port(tcp_header->dest, T_RULES[i].dstpt)) {
						/* Check whether to BLOCK the packet */
						if(T_RULES[i].block == 1) {
							printk(KERN_INFO"firewall: Blocking Outgoing TCP pkts\n");
							return NF_DROP;
						} else {
							if(T_RULES[i].block == 0) {
								printk(KERN_INFO"firewall: Unblocking all Outgoing TCP pkts");
								return NF_ACCEPT;
							}
						}
					}
				}
			}
			/* Check if the rule has protocol field set to UDP */
			if((T_RULES[i].proto == 2) && (ip_header->protocol == 17)) {
				/* Check IP address */
				if(compare_ip((unsigned int)ip_header->daddr, T_RULES[i].srcip)) {
					/* Check the port number */
					if(compare_port(tcp_header->dest, T_RULES[i].dstpt)) {
						/* Check whether to BLOCK the packet */
						if(T_RULES[i].block == 1) {
							printk(KERN_INFO"firewall: Blocking Outgoing UDP pkts\n");
							return NF_DROP;
						} else {
							if(T_RULES[i].block == 0) {
								printk(KERN_INFO"firewall: Unblocking all Outgoing UDP pkts");
								return NF_ACCEPT;
							}
						}
					}
				} 	
			}	
		}
	}
	return NF_ACCEPT;
}

