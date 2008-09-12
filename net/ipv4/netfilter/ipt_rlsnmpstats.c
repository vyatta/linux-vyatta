/*
 *  Copyright 2006, Vyatta, Inc.
 *
 *  GNU General Public License
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2,
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301 USA
 *
 *
 * Module: ipt_rlsnmpstats.c
 *
 * Author: Michael Larson
 * Date: 2005
 */

#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/uaccess.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4/ipt_rlsnmpstats.h>
#include <linux/netfilter/x_tables.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

static struct rl_data {
	unsigned long in_snmp_packet;
	unsigned long in_bad_ver;
	unsigned long in_bad_comm_name;
	unsigned long in_bad_comm_use;
	unsigned long in_asn_parse_err;
	unsigned long in_too_big;
	unsigned long in_no_such_name;
	unsigned long in_bad_val;
	unsigned long in_read_only;
	unsigned long in_gen_err;
	unsigned long in_total_req_var;
	unsigned long in_set_var;
	unsigned long in_get_request;
	unsigned long in_set_request;
	unsigned long in_get_response;
	unsigned long in_get_next;
	unsigned long in_trap;
	unsigned long in_silent_drop;
	unsigned long in_proxy_drop;
	unsigned long in_commit_pending_drop;
	unsigned long in_throttle_drop;

	unsigned long out_snmp_packet;
	unsigned long out_too_big;
	unsigned long out_no_such_name;
	unsigned long out_bad_val;
	unsigned long out_gen_err;
	unsigned long out_get_request;
	unsigned long out_get_next;
	unsigned long out_set_request;
	unsigned long out_get_response;
	unsigned long out_trap;
} g_rl_data;

/*
 * Application layer address mapping mimics the NAT mapping, but
 * only for the first octet in this case (a more flexible system
 * can be implemented if needed).
 */
struct oct1_map {
	u_int8_t from;
	u_int8_t to;
};

static int snmp_parse_mangle(unsigned char *msg,
			     u_int16_t len,
			     const struct oct1_map *map,
			     u_int16_t *check, u_int16_t out_flag);

/*
 *
 * MATCHING STUFF HERE.
 *
 */

static bool match(const struct sk_buff *skb,
		  const struct net_device *in, const struct net_device *out,
		  const struct xt_match *match, const void *matchinfo,
		  int offset, unsigned int protoff, bool *hotdrop)
{
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *udph = (struct udphdr *)((u_int32_t *) iph + iph->ihl);
	u_int16_t udplen = ntohs(udph->len);
	u_int16_t paylen = udplen - sizeof(struct udphdr);
	/*   int dir = CTINFO2DIR(ctinfo); */
	struct oct1_map map;
	u_int16_t out_flag;

	if (iph->protocol != 17)
		return 1;

	if ((udph->dest) == 161)	/*snmp port */
		return 1;

	if (in != NULL)
		out_flag = 0;
	else
		out_flag = 1;

	return snmp_parse_mangle((unsigned char *)udph + sizeof(struct udphdr),
				 paylen, &map, &udph->check, out_flag);
}

static bool checkentry(const char *tablename,
		       const void *ip,
		       const struct xt_match *match,
		       void *matchinfo, unsigned int hook_mask)
{
	if (hook_mask & ~((1 << NF_INET_LOCAL_IN) | (1 << NF_INET_LOCAL_OUT))) {
		pr_warning
		    ("ipt_rlsnmpstats: only valid with the FILTER table.\n");
		return 0;
	}

	return 1;
}

static struct xt_match rlsnmpstats_match = {
	.name = "rlsnmpstats",
	.family = AF_INET,
	.match = match,
	.checkentry = checkentry,
	.me = THIS_MODULE
};

/*
 * This function is called then the /proc file is read
 *
 */
static int snmpstat_proc_show(struct seq_file *seq, void *offset)
{
	seq_printf(seq, "SNMP statistics:\n"
		   " Input:\n"
		   "  Packets: %ld, Bad versions: %ld, Bad community names: %ld,\n"
		   "  Bad community uses: %ld, ASN parse errors: %ld,\n"
		   "  Too bigs: %ld, No such names: %ld, Bad values: %ld,\n"
		   "  Read onlys: %ld, General errors: %ld,\n"
		   "  Total request varbinds: %ld, Total set varbinds: %ld,\n"
		   "  Get requests: %ld, Get nexts: %ld, Set requests: %ld,\n"
		   "  Get responses: %ld, Traps: %ld\n",
		   g_rl_data.in_snmp_packet, g_rl_data.in_bad_ver,
		   g_rl_data.in_bad_comm_name, g_rl_data.in_bad_comm_use,
		   g_rl_data.in_asn_parse_err, g_rl_data.in_too_big,
		   g_rl_data.in_no_such_name, g_rl_data.in_bad_val,
		   g_rl_data.in_read_only, g_rl_data.in_gen_err,
		   g_rl_data.in_total_req_var, g_rl_data.in_set_var,
		   g_rl_data.in_get_request, g_rl_data.in_get_next,
		   g_rl_data.in_set_request, g_rl_data.in_get_response,
		   g_rl_data.in_trap);
#if 0
	seq_printf(seq, "  Silent drops: %ld, Proxy drops: %ld, "
		   "Commit pending drops: %ld,\n"
		   "  Throttle drops: %ld,\n"
		   g_rl_data.in_silent_drop, g_rl_data.in_proxy_drop,
		   g_rl_data.in_commit_pending_drop,
		   g_rl_data.in_throttle_drop);
#endif
	seq_printf(seq,
		   " Output:\n"
		   "  Packets: %ld, Too bigs: %ld, No such names: %ld,\n"
		   "  Bad values: %ld, General errors: %ld,\n"
		   "  Get requests: %ld, Get nexts: %ld, Set requests: %ld,\n"
		   "  Get responses: %ld, Traps: %ld\n",
		   g_rl_data.out_snmp_packet, g_rl_data.out_too_big,
		   g_rl_data.out_no_such_name, g_rl_data.out_bad_val,
		   g_rl_data.out_gen_err, g_rl_data.out_get_request,
		   g_rl_data.out_get_next, g_rl_data.out_set_request,
		   g_rl_data.out_get_response, g_rl_data.out_trap);
	return 0;
}

static ssize_t snmpstat_write(struct file *file, const char __user *buf,
			      size_t buflen, loff_t *offset)
{
	memset(&g_rl_data, 0, sizeof(g_rl_data));
	return 0;
}

static int snmpstat_open(struct inode *inode, struct file *file)
{
	return single_open(file, snmpstat_proc_show, NULL);
}

static const struct file_operations snmpstats_fops = {
	.owner	 = THIS_MODULE,
	.open    = snmpstat_open,
	.read    = seq_read,
	.write	 = snmpstat_write,
	.llseek  = seq_lseek,
	.release = single_release,
};

static int __init init(void)
{
	proc_net_fops_create(&init_net, "snmpstats", 0, &snmpstats_fops);

	return xt_register_match(&rlsnmpstats_match);
}
static void __exit fini(void)
{
	proc_net_remove(&init_net, "snmpstats");
	xt_unregister_match(&rlsnmpstats_match);
}

module_init(init);
module_exit(fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Larson");
MODULE_DESCRIPTION("netfilter RouteLogics snmp statistics");

/*
 *
 * SNMP PARSE MATCH STUFF HERE
 *
 */

#define SNMP_PORT 161
#define SNMP_TRAP_PORT 162
#define NOCT1(n) (u_int8_t )((n) & 0xff)

static int debug = 1;

/*****************************************************************************
 *
 * Basic ASN.1 decoding routines (gxsnmp author Dirk Wisse)
 *
 *****************************************************************************/

/* Class */
#define ASN1_UNI 0		/* Universal */
#define ASN1_APL 1		/* Application */
#define ASN1_CTX 2		/* Context */
#define ASN1_PRV 3		/* Private */

/* Tag */
#define ASN1_EOC 0		/* End Of Contents */
#define ASN1_BOL 1		/* Boolean */
#define ASN1_INT 2		/* Integer */
#define ASN1_BTS 3		/* Bit String */
#define ASN1_OTS 4		/* Octet String */
#define ASN1_NUL 5		/* Null */
#define ASN1_OJI 6		/* Object Identifier  */
#define ASN1_OJD 7		/* Object Description */
#define ASN1_EXT 8		/* External */
#define ASN1_SEQ 16		/* Sequence */
#define ASN1_SET 17		/* Set */
#define ASN1_NUMSTR 18		/* Numerical String */
#define ASN1_PRNSTR 19		/* Printable String */
#define ASN1_TEXSTR 20		/* Teletext String */
#define ASN1_VIDSTR 21		/* Video String */
#define ASN1_IA5STR 22		/* IA5 String */
#define ASN1_UNITIM 23		/* Universal Time */
#define ASN1_GENTIM 24		/* General Time */
#define ASN1_GRASTR 25		/* Graphical String */
#define ASN1_VISSTR 26		/* Visible String */
#define ASN1_GENSTR 27		/* General String */

/* Primitive / Constructed methods*/
#define ASN1_PRI 0		/* Primitive */
#define ASN1_CON 1		/* Constructed */

/*
 * Error codes.
 */
#define ASN1_ERR_NOERROR 0
#define ASN1_ERR_DEC_EMPTY 2
#define ASN1_ERR_DEC_EOC_MISMATCH 3
#define ASN1_ERR_DEC_LENGTH_MISMATCH 4
#define ASN1_ERR_DEC_BADVALUE 5

/*
 * ASN.1 context.
 */
struct asn1_ctx {
	int error;		/* Error condition */
	unsigned char *pointer;	/* Octet just to be decoded */
	unsigned char *begin;	/* First octet */
	unsigned char *end;	/* Octet after last octet */
};

/*
 * Octet string (not null terminated)
 */
struct asn1_octstr {
	unsigned char *data;
	unsigned int len;
};

static void asn1_open(struct asn1_ctx *ctx,
		      unsigned char *buf, unsigned int len)
{
	ctx->begin = buf;
	ctx->end = buf + len;
	ctx->pointer = buf;
	ctx->error = ASN1_ERR_NOERROR;
}

static unsigned char asn1_octet_decode(struct asn1_ctx *ctx, unsigned char *ch)
{
	if (ctx->pointer >= ctx->end) {
		ctx->error = ASN1_ERR_DEC_EMPTY;
		return 0;
	}
	*ch = *(ctx->pointer)++;
	return 1;
}

static unsigned char asn1_tag_decode(struct asn1_ctx *ctx, unsigned int *tag)
{
	unsigned char ch;

	*tag = 0;

	do {
		if (!asn1_octet_decode(ctx, &ch))
			return 0;
		*tag <<= 7;
		*tag |= ch & 0x7F;
	} while ((ch & 0x80) == 0x80);
	return 1;
}

static unsigned char asn1_id_decode(struct asn1_ctx *ctx,
				    unsigned int *cls,
				    unsigned int *con, unsigned int *tag)
{
	unsigned char ch;

	if (!asn1_octet_decode(ctx, &ch))
		return 0;

	*cls = (ch & 0xC0) >> 6;
	*con = (ch & 0x20) >> 5;
	*tag = (ch & 0x1F);

	if (*tag == 0x1F) {
		if (!asn1_tag_decode(ctx, tag))
			return 0;
	}
	return 1;
}

static unsigned char asn1_length_decode(struct asn1_ctx *ctx,
					unsigned int *def, unsigned int *len)
{
	unsigned char ch, cnt;

	if (!asn1_octet_decode(ctx, &ch))
		return 0;

	if (ch == 0x80)
		*def = 0;
	else {
		*def = 1;

		if (ch < 0x80)
			*len = ch;
		else {
			cnt = (unsigned char)(ch & 0x7F);
			*len = 0;

			while (cnt > 0) {
				if (!asn1_octet_decode(ctx, &ch))
					return 0;
				*len <<= 8;
				*len |= ch;
				cnt--;
			}
		}
	}
	return 1;
}

static unsigned char asn1_header_decode(struct asn1_ctx *ctx,
					unsigned char **eoc,
					unsigned int *cls,
					unsigned int *con, unsigned int *tag)
{
	unsigned int def, len;

	if (!asn1_id_decode(ctx, cls, con, tag))
		return 0;

	if (!asn1_length_decode(ctx, &def, &len))
		return 0;

	if (def)
		*eoc = ctx->pointer + len;
	else
		*eoc = NULL;
	return 1;
}

static unsigned char asn1_eoc_decode(struct asn1_ctx *ctx, unsigned char *eoc)
{
	unsigned char ch;

	if (eoc == NULL) {
		if (!asn1_octet_decode(ctx, &ch))
			return 0;

		if (ch != 0x00) {
			ctx->error = ASN1_ERR_DEC_EOC_MISMATCH;
			return 0;
		}

		if (!asn1_octet_decode(ctx, &ch)) {
			return 0;
		}

		if (ch != 0x00) {
			ctx->error = ASN1_ERR_DEC_EOC_MISMATCH;
			return 0;
		}
		return 1;
	} else {
		if (ctx->pointer != eoc) {
			ctx->error = ASN1_ERR_DEC_LENGTH_MISMATCH;
			return 0;
		}
		return 1;
	}
}

static unsigned char asn1_null_decode(struct asn1_ctx *ctx, unsigned char *eoc)
{
	ctx->pointer = eoc;
	return 1;
}

static unsigned char asn1_long_decode(struct asn1_ctx *ctx,
				      unsigned char *eoc, long *integer)
{
	unsigned char ch;
	unsigned int len;

	if (!asn1_octet_decode(ctx, &ch))
		return 0;

	*integer = (signed char)ch;
	len = 1;

	while (ctx->pointer < eoc) {
		if (++len > sizeof(long)) {
			ctx->error = ASN1_ERR_DEC_BADVALUE;
			return 0;
		}

		if (!asn1_octet_decode(ctx, &ch))
			return 0;

		*integer <<= 8;
		*integer |= ch;
	}
	return 1;
}

static unsigned char asn1_uint_decode(struct asn1_ctx *ctx,
				      unsigned char *eoc, unsigned int *integer)
{
	unsigned char ch;
	unsigned int len;

	if (!asn1_octet_decode(ctx, &ch))
		return 0;

	*integer = ch;
	if (ch == 0)
		len = 0;
	else
		len = 1;

	while (ctx->pointer < eoc) {
		if (++len > sizeof(unsigned int)) {
			ctx->error = ASN1_ERR_DEC_BADVALUE;
			return 0;
		}

		if (!asn1_octet_decode(ctx, &ch))
			return 0;

		*integer <<= 8;
		*integer |= ch;
	}
	return 1;
}

static unsigned char asn1_ulong_decode(struct asn1_ctx *ctx,
				       unsigned char *eoc,
				       unsigned long *integer)
{
	unsigned char ch;
	unsigned int len;

	if (!asn1_octet_decode(ctx, &ch))
		return 0;

	*integer = ch;
	if (ch == 0)
		len = 0;
	else
		len = 1;

	while (ctx->pointer < eoc) {
		if (++len > sizeof(unsigned long)) {
			ctx->error = ASN1_ERR_DEC_BADVALUE;
			return 0;
		}

		if (!asn1_octet_decode(ctx, &ch))
			return 0;

		*integer <<= 8;
		*integer |= ch;
	}
	return 1;
}

static unsigned char asn1_octets_decode(struct asn1_ctx *ctx,
					unsigned char *eoc,
					unsigned char **octets,
					unsigned int *len)
{
	unsigned char *ptr;

	*len = 0;

	*octets = kmalloc(eoc - ctx->pointer, GFP_ATOMIC);
	if (*octets == NULL) {
		if (net_ratelimit())
			printk("OOM in bsalg (%d)\n", __LINE__);
		return 0;
	}

	ptr = *octets;
	while (ctx->pointer < eoc) {
		if (!asn1_octet_decode(ctx, (unsigned char *)ptr++)) {
			kfree(*octets);
			*octets = NULL;
			return 0;
		}
		(*len)++;
	}
	return 1;
}

static unsigned char asn1_subid_decode(struct asn1_ctx *ctx,
				       unsigned long *subid)
{
	unsigned char ch;

	*subid = 0;

	do {
		if (!asn1_octet_decode(ctx, &ch))
			return 0;

		*subid <<= 7;
		*subid |= ch & 0x7F;
	} while ((ch & 0x80) == 0x80);
	return 1;
}

static unsigned char asn1_oid_decode(struct asn1_ctx *ctx,
				     unsigned char *eoc,
				     unsigned long **oid, unsigned int *len)
{
	unsigned long subid;
	unsigned int size;
	unsigned long *optr;

	size = eoc - ctx->pointer + 1;
	*oid = kmalloc(size * sizeof(unsigned long), GFP_ATOMIC);
	if (*oid == NULL) {
		if (net_ratelimit())
			printk("OOM in bsalg (%d)\n", __LINE__);
		return 0;
	}

	optr = *oid;

	if (!asn1_subid_decode(ctx, &subid)) {
		kfree(*oid);
		*oid = NULL;
		return 0;
	}

	if (subid < 40) {
		optr[0] = 0;
		optr[1] = subid;
	} else if (subid < 80) {
		optr[0] = 1;
		optr[1] = subid - 40;
	} else {
		optr[0] = 2;
		optr[1] = subid - 80;
	}

	*len = 2;
	optr += 2;

	while (ctx->pointer < eoc) {
		if (++(*len) > size) {
			ctx->error = ASN1_ERR_DEC_BADVALUE;
			kfree(*oid);
			*oid = NULL;
			return 0;
		}

		if (!asn1_subid_decode(ctx, optr++)) {
			kfree(*oid);
			*oid = NULL;
			return 0;
		}
	}
	return 1;
}

/*****************************************************************************
 *
 * SNMP decoding routines (gxsnmp author Dirk Wisse)
 *
 *****************************************************************************/

/* SNMP Versions */
#define SNMP_V1 0
#define SNMP_V2C 1
#define SNMP_V2 2
#define SNMP_V3 3

/* Default Sizes */
#define SNMP_SIZE_COMM 256
#define SNMP_SIZE_OBJECTID 128
#define SNMP_SIZE_BUFCHR 256
#define SNMP_SIZE_BUFINT 128
#define SNMP_SIZE_SMALLOBJECTID 16

/* Requests */
#define SNMP_PDU_GET 0
#define SNMP_PDU_NEXT 1
#define SNMP_PDU_RESPONSE 2
#define SNMP_PDU_SET 3
#define SNMP_PDU_TRAP1 4
#define SNMP_PDU_BULK 5
#define SNMP_PDU_INFORM 6
#define SNMP_PDU_TRAP2 7

/* Errors */
#define SNMP_NOERROR 0
#define SNMP_TOOBIG 1
#define SNMP_NOSUCHNAME 2
#define SNMP_BADVALUE 3
#define SNMP_READONLY 4
#define SNMP_GENERROR 5
#define SNMP_NOACCESS 6
#define SNMP_WRONGTYPE 7
#define SNMP_WRONGLENGTH 8
#define SNMP_WRONGENCODING 9
#define SNMP_WRONGVALUE 10
#define SNMP_NOCREATION 11
#define SNMP_INCONSISTENTVALUE 12
#define SNMP_RESOURCEUNAVAILABLE 13
#define SNMP_COMMITFAILED 14
#define SNMP_UNDOFAILED 15
#define SNMP_AUTHORIZATIONERROR 16
#define SNMP_NOTWRITABLE 17
#define SNMP_INCONSISTENTNAME 18

/* General SNMP V1 Traps */
#define SNMP_TRAP_COLDSTART 0
#define SNMP_TRAP_WARMSTART 1
#define SNMP_TRAP_LINKDOWN 2
#define SNMP_TRAP_LINKUP 3
#define SNMP_TRAP_AUTFAILURE 4
#define SNMP_TRAP_EQPNEIGHBORLOSS 5
#define SNMP_TRAP_ENTSPECIFIC 6

/* SNMPv1 Types */
#define SNMP_NULL                0
#define SNMP_INTEGER             1	/* l  */
#define SNMP_OCTETSTR            2	/* c  */
#define SNMP_DISPLAYSTR          2	/* c  */
#define SNMP_OBJECTID            3	/* ul */
#define SNMP_IPADDR              4	/* uc */
#define SNMP_COUNTER             5	/* ul */
#define SNMP_GAUGE               6	/* ul */
#define SNMP_TIMETICKS           7	/* ul */
#define SNMP_OPAQUE              8	/* c  */

/* Additional SNMPv2 Types */
#define SNMP_UINTEGER            5	/* ul */
#define SNMP_BITSTR              9	/* uc */
#define SNMP_NSAP               10	/* uc */
#define SNMP_COUNTER64          11	/* ul */
#define SNMP_NOSUCHOBJECT       12
#define SNMP_NOSUCHINSTANCE     13
#define SNMP_ENDOFMIBVIEW       14

union snmp_syntax {
	unsigned char uc[0];	/* 8 bit unsigned */
	char c[0];		/* 8 bit signed */
	unsigned long ul[0];	/* 32 bit unsigned */
	long l[0];		/* 32 bit signed */
};

struct snmp_object {
	unsigned long *id;
	unsigned int id_len;
	unsigned short type;
	unsigned int syntax_len;
	union snmp_syntax syntax;
};

struct snmp_request {
	unsigned long id;
	unsigned int error_status;
	unsigned int error_index;
};

struct snmp_v1_trap {
	unsigned long *id;
	unsigned int id_len;
	unsigned long ip_address;	/* pointer  */
	unsigned int general;
	unsigned int specific;
	unsigned long time;
};

/* SNMP types */
#define SNMP_IPA    0
#define SNMP_CNT    1
#define SNMP_GGE    2
#define SNMP_TIT    3
#define SNMP_OPQ    4
#define SNMP_C64    6

/* SNMP errors */
#define SERR_NSO    0
#define SERR_NSI    1
#define SERR_EOM    2

static void mangle_address(unsigned char *begin,
			   unsigned char *addr,
			   const struct oct1_map *map, u_int16_t * check);
struct snmp_cnv {
	unsigned int class;
	unsigned int tag;
	int syntax;
};

static struct snmp_cnv snmp_conv[] = {
	{ASN1_UNI, ASN1_NUL, SNMP_NULL},
	{ASN1_UNI, ASN1_INT, SNMP_INTEGER},
	{ASN1_UNI, ASN1_OTS, SNMP_OCTETSTR},
	{ASN1_UNI, ASN1_OTS, SNMP_DISPLAYSTR},
	{ASN1_UNI, ASN1_OJI, SNMP_OBJECTID},
	{ASN1_APL, SNMP_IPA, SNMP_IPADDR},
	{ASN1_APL, SNMP_CNT, SNMP_COUNTER},	/* Counter32 */
	{ASN1_APL, SNMP_GGE, SNMP_GAUGE},	/* Gauge32 == Unsigned32  */
	{ASN1_APL, SNMP_TIT, SNMP_TIMETICKS},
	{ASN1_APL, SNMP_OPQ, SNMP_OPAQUE},

	/* SNMPv2 data types and errors */
	{ASN1_UNI, ASN1_BTS, SNMP_BITSTR},
	{ASN1_APL, SNMP_C64, SNMP_COUNTER64},
	{ASN1_CTX, SERR_NSO, SNMP_NOSUCHOBJECT},
	{ASN1_CTX, SERR_NSI, SNMP_NOSUCHINSTANCE},
	{ASN1_CTX, SERR_EOM, SNMP_ENDOFMIBVIEW},
	{0, 0, -1}
};

static unsigned char snmp_tag_cls2syntax(unsigned int tag,
					 unsigned int cls,
					 unsigned short *syntax)
{
	struct snmp_cnv *cnv;

	cnv = snmp_conv;

	while (cnv->syntax != -1) {
		if (cnv->tag == tag && cnv->class == cls) {
			*syntax = cnv->syntax;
			return 1;
		}
		cnv++;
	}
	return 0;
}

static unsigned char snmp_object_decode(struct asn1_ctx *ctx,
					struct snmp_object **obj)
{
	unsigned int cls, con, tag, len, idlen;
	unsigned short type;
	unsigned char *eoc, *end, *p;
	unsigned long *lp, *id;
	unsigned long ul;
	long l;

	*obj = NULL;
	id = NULL;

	if (!asn1_header_decode(ctx, &eoc, &cls, &con, &tag))
		return 0;

	if (cls != ASN1_UNI || con != ASN1_CON || tag != ASN1_SEQ)
		return 0;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		return 0;

	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_OJI)
		return 0;

	if (!asn1_oid_decode(ctx, end, &id, &idlen))
		return 0;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag)) {
		kfree(id);
		return 0;
	}

	if (con != ASN1_PRI) {
		kfree(id);
		return 0;
	}

	if (!snmp_tag_cls2syntax(tag, cls, &type)) {
		kfree(id);
		return 0;
	}

	switch (type) {
	case SNMP_INTEGER:
		len = sizeof(long);
		if (!asn1_long_decode(ctx, end, &l)) {
			kfree(id);
			return 0;
		}
		*obj = kmalloc(sizeof(struct snmp_object) + len, GFP_ATOMIC);
		if (*obj == NULL) {
			kfree(id);
			if (net_ratelimit())
				printk("OOM in bsalg (%d)\n", __LINE__);
			return 0;
		}
		(*obj)->syntax.l[0] = l;
		break;
	case SNMP_OCTETSTR:
	case SNMP_OPAQUE:
		if (!asn1_octets_decode(ctx, end, &p, &len)) {
			kfree(id);
			return 0;
		}
		*obj = kmalloc(sizeof(struct snmp_object) + len, GFP_ATOMIC);
		if (*obj == NULL) {
			kfree(id);
			if (net_ratelimit())
				printk("OOM in bsalg (%d)\n", __LINE__);
			return 0;
		}
		memcpy((*obj)->syntax.c, p, len);
		kfree(p);
		break;
	case SNMP_NULL:
	case SNMP_NOSUCHOBJECT:
	case SNMP_NOSUCHINSTANCE:
	case SNMP_ENDOFMIBVIEW:
		len = 0;
		*obj = kmalloc(sizeof(struct snmp_object), GFP_ATOMIC);
		if (*obj == NULL) {
			kfree(id);
			if (net_ratelimit())
				printk("OOM in bsalg (%d)\n", __LINE__);
			return 0;
		}
		if (!asn1_null_decode(ctx, end)) {
			kfree(id);
			kfree(*obj);
			*obj = NULL;
			return 0;
		}
		break;
	case SNMP_OBJECTID:
		if (!asn1_oid_decode(ctx, end, (unsigned long **)&lp, &len)) {
			kfree(id);
			return 0;
		}
		len *= sizeof(unsigned long);
		*obj = kmalloc(sizeof(struct snmp_object) + len, GFP_ATOMIC);
		if (*obj == NULL) {
			kfree(id);
			if (net_ratelimit())
				printk("OOM in bsalg (%d)\n", __LINE__);
			return 0;
		}
		memcpy((*obj)->syntax.ul, lp, len);
		kfree(lp);
		break;
	case SNMP_IPADDR:
		if (!asn1_octets_decode(ctx, end, &p, &len)) {
			kfree(id);
			return 0;
		}
		if (len != 4) {
			kfree(p);
			kfree(id);
			return 0;
		}
		*obj = kmalloc(sizeof(struct snmp_object) + len, GFP_ATOMIC);
		if (*obj == NULL) {
			kfree(p);
			kfree(id);
			if (net_ratelimit())
				printk("OOM in bsalg (%d)\n", __LINE__);
			return 0;
		}
		memcpy((*obj)->syntax.uc, p, len);
		kfree(p);
		break;
	case SNMP_COUNTER:
	case SNMP_GAUGE:
	case SNMP_TIMETICKS:
		len = sizeof(unsigned long);
		if (!asn1_ulong_decode(ctx, end, &ul)) {
			kfree(id);
			return 0;
		}
		*obj = kmalloc(sizeof(struct snmp_object) + len, GFP_ATOMIC);
		if (*obj == NULL) {
			kfree(id);
			if (net_ratelimit())
				printk("OOM in bsalg (%d)\n", __LINE__);
			return 0;
		}
		(*obj)->syntax.ul[0] = ul;
		break;
	default:
		kfree(id);
		return 0;
	}

	(*obj)->syntax_len = len;
	(*obj)->type = type;
	(*obj)->id = id;
	(*obj)->id_len = idlen;

	if (!asn1_eoc_decode(ctx, eoc)) {
		kfree(id);
		kfree(*obj);
		*obj = NULL;
		return 0;
	}
	return 1;
}

static unsigned char snmp_request_decode(struct asn1_ctx *ctx,
					 struct snmp_request *request)
{
	unsigned int cls, con, tag;
	unsigned char *end;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		return 0;

	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_INT)
		return 0;

	if (!asn1_ulong_decode(ctx, end, &request->id))
		return 0;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		return 0;

	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_INT)
		return 0;

	if (!asn1_uint_decode(ctx, end, &request->error_status))
		return 0;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		return 0;

	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_INT)
		return 0;

	if (!asn1_uint_decode(ctx, end, &request->error_index))
		return 0;

	return 1;
}

static unsigned char snmp_trap_decode(struct asn1_ctx *ctx,
				      struct snmp_v1_trap *trap,
				      const struct oct1_map *map,
				      u_int16_t * check)
{
	unsigned int cls, con, tag, len;
	unsigned char *end;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		return 0;

	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_OJI)
		return 0;

	if (!asn1_oid_decode(ctx, end, &trap->id, &trap->id_len))
		return 0;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		goto err_id_free;

	if (!((cls == ASN1_APL && con == ASN1_PRI && tag == SNMP_IPA) ||
	      (cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_OTS)))
		goto err_id_free;

	if (!asn1_octets_decode
	    (ctx, end, (unsigned char **)&trap->ip_address, &len))
		goto err_id_free;

	/* IPv4 only */
	if (len != 4)
		goto err_addr_free;

	mangle_address(ctx->begin, ctx->pointer - 4, map, check);

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		goto err_addr_free;

	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_INT)
		goto err_addr_free;;

	if (!asn1_uint_decode(ctx, end, &trap->general))
		goto err_addr_free;;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		goto err_addr_free;

	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_INT)
		goto err_addr_free;

	if (!asn1_uint_decode(ctx, end, &trap->specific))
		goto err_addr_free;

	if (!asn1_header_decode(ctx, &end, &cls, &con, &tag))
		goto err_addr_free;

	if (!((cls == ASN1_APL && con == ASN1_PRI && tag == SNMP_TIT) ||
	      (cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_INT)))
		goto err_addr_free;

	if (!asn1_ulong_decode(ctx, end, &trap->time))
		goto err_addr_free;

	return 1;

err_id_free:
	kfree(trap->id);

err_addr_free:
	kfree((unsigned long *)trap->ip_address);

	return 0;
}

/*****************************************************************************
 *
 * Misc. routines
 *
 *****************************************************************************/

static void hex_dump(unsigned char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (i && !(i % 16))
			printk("\n");
		printk("%02x ", *(buf + i));
	}
	printk("\n");
}

/*
 * Fast checksum update for possibly oddly-aligned UDP byte, from the
 * code example in the draft.
 */
static void fast_csum(unsigned char *csum,
		      const unsigned char *optr,
		      const unsigned char *nptr, int odd)
{
	long x, old, new;

	x = csum[0] * 256 + csum[1];

	x = ~x & 0xFFFF;

	if (odd)
		old = optr[0] * 256;
	else
		old = optr[0];

	x -= old & 0xFFFF;
	if (x <= 0) {
		x--;
		x &= 0xFFFF;
	}

	if (odd)
		new = nptr[0] * 256;
	else
		new = nptr[0];

	x += new & 0xFFFF;
	if (x & 0x10000) {
		x++;
		x &= 0xFFFF;
	}

	x = ~x & 0xFFFF;
	csum[0] = x / 256;
	csum[1] = x & 0xFF;
}

/*
 * Mangle IP address.
 * - begin points to the start of the snmp messgae
 *      - addr points to the start of the address
 */
static void mangle_address(unsigned char *begin,
			   unsigned char *addr,
			   const struct oct1_map *map, u_int16_t * check)
{
	if (map->from == NOCT1(*addr)) {
		u_int32_t old;

		if (debug)
			memcpy(&old, (unsigned char *)addr, sizeof(old));

		*addr = map->to;

		/* Update UDP checksum if being used */
		if (*check) {
			unsigned char odd = !((addr - begin) % 2);

			fast_csum((unsigned char *)check,
				  &map->from, &map->to, odd);

		}

		if (debug)
			printk(KERN_DEBUG "bsalg: mapped %u.%u.%u.%u to "
			       "%u.%u.%u.%u\n", NIPQUAD(old), NIPQUAD(*addr));
	}
}

/*
 * Parse and mangle SNMP message according to mapping.
 * (And this is the fucking 'basic' method).
 */
static int snmp_parse_mangle(unsigned char *msg,
			     u_int16_t len,
			     const struct oct1_map *map,
			     u_int16_t * check, u_int16_t out_flag)
{
	unsigned char *eoc, *end;
	unsigned int cls, con, tag, vers, pdutype;
	struct asn1_ctx ctx;
	struct asn1_octstr comm;
	struct snmp_object **obj;

	if (debug > 1)
		hex_dump(msg, len);

	asn1_open(&ctx, msg, len);

	/*
	 * Start of SNMP message.
	 */
	if (!asn1_header_decode(&ctx, &eoc, &cls, &con, &tag))
		return 0;
	if (cls != ASN1_UNI || con != ASN1_CON || tag != ASN1_SEQ)
		return 0;

	/*
	 * Version 1 or 2 handled.
	 */
	if (!asn1_header_decode(&ctx, &end, &cls, &con, &tag))
		return 0;
	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_INT)
		return 0;
	if (!asn1_uint_decode(&ctx, end, &vers))
		return 0;
	if (debug > 1)
		printk(KERN_DEBUG "bsalg: snmp version: %u\n", vers + 1);
	if (vers > 1) {
		if (!out_flag) {
			++g_rl_data.in_bad_ver;
		}
		return 0;
	}

	/*
	 * Community.
	 */
	if (!asn1_header_decode(&ctx, &end, &cls, &con, &tag))
		return 0;
	if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_OTS)
		return 0;
	if (!asn1_octets_decode(&ctx, end, &comm.data, &comm.len))
		return 0;
	if (debug > 1) {
		unsigned int i;

		printk(KERN_DEBUG "bsalg: community: ");
		for (i = 0; i < comm.len; i++)
			printk("%c", comm.data[i]);
		printk("\n");
	}
	kfree(comm.data);

	/*
	 * PDU type
	 */
	if (!asn1_header_decode(&ctx, &eoc, &cls, &con, &pdutype))
		return 0;

	if (out_flag) {
		++g_rl_data.out_snmp_packet;
	} else {
		++g_rl_data.in_snmp_packet;
	}
	/*
	   printk("out_flag: %d, pdutype: %d\n", out_flag, pdutype);
	 */
	if (cls != ASN1_CTX || con != ASN1_CON)
		return 0;
	if (debug > 1) {
		unsigned char *pdus[] = {
			[SNMP_PDU_GET] = "get",
			[SNMP_PDU_NEXT] = "get-next",
			[SNMP_PDU_RESPONSE] = "response",
			[SNMP_PDU_SET] = "set",
			[SNMP_PDU_TRAP1] = "trapv1",
			[SNMP_PDU_BULK] = "bulk",
			[SNMP_PDU_INFORM] = "inform",
			[SNMP_PDU_TRAP2] = "trapv2"
		};

		if (pdutype > SNMP_PDU_TRAP2)
			printk(KERN_DEBUG "bsalg: bad pdu type %u\n", pdutype);
		else
			printk(KERN_DEBUG "bsalg: pdu: %s\n", pdus[pdutype]);
	}
	/*
	   if (pdutype != SNMP_PDU_RESPONSE &&
	   pdutype != SNMP_PDU_TRAP1 && pdutype != SNMP_PDU_TRAP2)
	   return 1;
	 */

	if (out_flag) {
		if (pdutype == SNMP_PDU_GET) {
			++g_rl_data.out_get_request;
		} else if (pdutype == SNMP_PDU_NEXT) {
			++g_rl_data.out_get_next;
		} else if (pdutype == SNMP_PDU_RESPONSE) {
			++g_rl_data.out_get_response;
		} else if (pdutype == SNMP_PDU_SET) {
			++g_rl_data.out_set_request;
		} else if (pdutype == SNMP_PDU_TRAP1
			   || pdutype == SNMP_PDU_TRAP2) {
			++g_rl_data.out_trap;
		}
	} else {
		if (pdutype == SNMP_PDU_GET) {
			++g_rl_data.in_get_request;
		} else if (pdutype == SNMP_PDU_RESPONSE) {
			++g_rl_data.in_get_response;
		} else if (pdutype == SNMP_PDU_NEXT) {
			++g_rl_data.in_get_next;
		} else if (pdutype == SNMP_PDU_SET) {
			++g_rl_data.in_set_request;
		} else if (pdutype == SNMP_PDU_TRAP1
			   || pdutype == SNMP_PDU_TRAP2) {
			++g_rl_data.in_trap;
		}
	}

	/*
	 * Request header or v1 trap
	 */
	if (pdutype == SNMP_PDU_TRAP1) {
		struct snmp_v1_trap trap;
		unsigned char ret = snmp_trap_decode(&ctx, &trap, map, check);

		/* Discard trap allocations regardless */
		kfree(trap.id);
		kfree((unsigned long *)trap.ip_address);

		if (!ret)
			return ret;

	} else {
		struct snmp_request req;

		if (!snmp_request_decode(&ctx, &req))
			return 0;

		if (req.error_status == SNMP_TOOBIG) {
			if (out_flag) {
				++g_rl_data.out_too_big;
			} else {
				++g_rl_data.in_too_big;
			}
		} else if (req.error_status == SNMP_NOSUCHNAME) {
			if (out_flag) {
				++g_rl_data.out_no_such_name;
			} else {
				++g_rl_data.in_no_such_name;
			}
		} else if (req.error_status == SNMP_BADVALUE) {
			if (out_flag) {
				++g_rl_data.out_bad_val;
			} else {
				++g_rl_data.in_bad_val;
			}
		} else if (req.error_status == SNMP_READONLY) {
			if (!out_flag) {
				++g_rl_data.in_read_only;
			}
		} else if (req.error_status == SNMP_GENERROR) {
			if (out_flag) {
				++g_rl_data.out_gen_err;
			} else {
				++g_rl_data.in_gen_err;
			}
		}

		if (debug > 1)
			printk(KERN_DEBUG
			       "bsalg: request: id=0x%lx error_status=%u "
			       "error_index=%u\n", req.id, req.error_status,
			       req.error_index);
	}

	/*
	 * Loop through objects, look for IP addresses to mangle.
	 */
	if (!asn1_header_decode(&ctx, &eoc, &cls, &con, &tag))
		return 0;

	if (cls != ASN1_UNI || con != ASN1_CON || tag != ASN1_SEQ)
		return 0;

	obj = kmalloc(sizeof(struct snmp_object), GFP_ATOMIC);
	if (obj == NULL) {
		if (net_ratelimit())
			printk(KERN_WARNING "OOM in bsalg(%d)\n", __LINE__);
		return 0;
	}

	while (!asn1_eoc_decode(&ctx, eoc)) {
		unsigned int i;

		if (!snmp_object_decode(&ctx, obj)) {
			if (*obj) {
				if ((*obj)->id)
					kfree((*obj)->id);
				kfree(*obj);
			}
			kfree(obj);
			return 0;
		}

		if (debug > 1) {
			printk(KERN_DEBUG "bsalg: object: ");
			for (i = 0; i < (*obj)->id_len; i++) {
				if (i > 0)
					printk(".");
				printk("%lu", (*obj)->id[i]);
			}
			printk(": type=%u\n", (*obj)->type);

		}

		if ((*obj)->type == SNMP_IPADDR)
			mangle_address(ctx.begin, ctx.pointer - 4, map, check);

		kfree((*obj)->id);
		kfree(*obj);
	}
	kfree(obj);

	if (!asn1_eoc_decode(&ctx, eoc))
		return 0;

	return 1;
}
