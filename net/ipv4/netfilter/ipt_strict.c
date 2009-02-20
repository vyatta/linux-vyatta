/* IP tables module for matching packets not routed to incoming interface
 *
 * (C) 2009 by Stephen Hemminger <shemminger@vyatta.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/if.h>
#include <linux/inetdevice.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv4/ipt_ecn.h>

MODULE_AUTHOR("Stephen Hemminger <shemminger@vyatta.com>");
MODULE_DESCRIPTION("Xtables: Strict End System match");
MODULE_LICENSE("GPL");

static bool strict_mt(const struct sk_buff *skb, const struct xt_match_param *par)
{
	struct in_device *in_dev;
	bool strong_es;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(skb->dev);
	strong_es = (in_dev && inet_addr_onlink(in_dev, ip_hdr(skb)->daddr, 0));
	rcu_read_unlock();

	return strong_es;
}

static struct xt_match strict_mt_reg __read_mostly = {
	.name		= "strict",
	.family		= NFPROTO_IPV4,
	.match		= strict_mt,
	.matchsize	= 0,
	.me		= THIS_MODULE,
};

static int __init strict_mt_init(void)
{
	return xt_register_match(&strict_mt_reg);
}

static void __exit strict_mt_exit(void)
{
	xt_unregister_match(&strict_mt_reg);
}

module_init(strict_mt_init);
module_exit(strict_mt_exit);
