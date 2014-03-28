#ifndef _NETFLTRHOOKS_H_
#define _NETFLTRHOOKS_H_

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#include "utils.h"

/* Netfilter hook functions for incoming and outgoing packets */
unsigned int in_hook_func(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff* ));
unsigned int out_hook_func(unsigned int hooknum, struct sk_buff* skb, const struct net_device* in, const struct net_device* out, int (*okfn)(struct sk_buff* ));

#endif /* _NETFLTRHOOKS_H_ */
