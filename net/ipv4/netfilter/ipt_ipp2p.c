#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ipt_ipp2p.h>
#include <net/tcp.h>
#include <net/udp.h>

#define get_u8(X, O)  (*(__u8 *)(X + O))
#define get_u16(X, O)  (*(__u16 *)(X + O))
#define get_u32(X, O)  (*(__u32 *)(X + O))

MODULE_AUTHOR("Eicke Friedrich/Klaus Degner <ipp2p@ipp2p.org>");
MODULE_DESCRIPTION("An extension to iptables to identify P2P traffic.");
MODULE_LICENSE("GPL");

/*Search for UDP eDonkey/eMule/Kad commands*/
static int udp_search_edk(const unsigned char *haystack, int packet_len)
{
	const unsigned char *t = haystack;
	t += 8;

	switch (t[0]) {
	case 0xe3:
		{		/*edonkey */
			switch (t[1]) {
				/* client -> server status request */
			case 0x96:
				if (packet_len == 14)
					return (IPP2P_EDK * 100) + 50;
				break;
				/* server -> client status request */
			case 0x97:
				if (packet_len == 42)
					return (IPP2P_EDK * 100) + 51;
				break;
				/* server description request */
				/* e3 2a ff f0 .. | size == 6 */
			case 0xa2:
				if ((packet_len == 14)
				    && (get_u16(t, 2) ==
					htons(0xfff0)))
					return (IPP2P_EDK * 100) + 52;
				break;
				/* server description response */
				/* e3 a3 ff f0 ..  | size > 40 && size < 200 */
			case 0x9a:
				if (packet_len == 26)
					return (IPP2P_EDK * 100) + 54;
				break;

			case 0x92:
				if (packet_len == 18)
					return (IPP2P_EDK * 100) + 55;
				break;
			}
			break;
		}
	case 0xe4:
		{
			switch (t[1]) {
				/* e4 20 .. | size == 43 */
			case 0x20:
				if ((packet_len == 43) && (t[2] != 0x00)
				    && (t[34] != 0x00))
					return (IPP2P_EDK * 100) + 60;
				break;
				/* e4 00 .. 00 | size == 35 ? */
			case 0x00:
				if ((packet_len == 35) && (t[26] == 0x00))
					return (IPP2P_EDK * 100) + 61;
				break;
				/* e4 10 .. 00 | size == 35 ? */
			case 0x10:
				if ((packet_len == 35) && (t[26] == 0x00))
					return (IPP2P_EDK * 100) + 62;
				break;
				/* e4 18 .. 00 | size == 35 ? */
			case 0x18:
				if ((packet_len == 35) && (t[26] == 0x00))
					return (IPP2P_EDK * 100) + 63;
				break;
				/* e4 52 .. | size = 44 */
			case 0x52:
				if (packet_len == 44)
					return (IPP2P_EDK * 100) + 64;
				break;
				/* e4 58 .. | size == 6 */
			case 0x58:
				if (packet_len == 14)
					return (IPP2P_EDK * 100) + 65;
				break;
				/* e4 59 .. | size == 2 */
			case 0x59:
				if (packet_len == 10)
					return (IPP2P_EDK * 100) + 66;
				break;
				/* e4 28 .. | packet_len == 52,77,102,127... */
			case 0x28:
				if (((packet_len - 52) % 25) == 0)
					return (IPP2P_EDK * 100) + 67;
				break;
				/* e4 50 xx xx | size == 4 */
			case 0x50:
				if (packet_len == 12)
					return (IPP2P_EDK * 100) + 68;
				break;
				/* e4 40 xx xx | size == 48 */
			case 0x40:
				if (packet_len == 56)
					return (IPP2P_EDK * 100) + 69;
				break;
			}
			break;
		}
	}

	return 0;
}

/*Search for UDP Gnutella commands*/
static int udp_search_gnu(const unsigned char *haystack, int packet_len)
{
	const unsigned char *t = haystack;
	t += 8;

	if (memcmp(t, "GND", 3) == 0)
		return (IPP2P_GNU * 100) + 51;
	if (memcmp(t, "GNUTELLA ", 9) == 0)
		return (IPP2P_GNU * 100) + 52;
	return 0;
}

/*Search for UDP KaZaA commands*/
static int udp_search_kazaa(const unsigned char *haystack, int packet_len)
{
	const unsigned char *t = haystack;

	if (t[packet_len - 1] == 0x00) {
		t += (packet_len - 6);
		if (memcmp(t, "KaZaA", 5) == 0)
			return IPP2P_KAZAA * 100 + 50;
	}

	return 0;
}

/*Search for UDP DirectConnect commands*/
static int
udp_search_directconnect(const unsigned char *haystack, int packet_len)
{
	const unsigned char *t = haystack;
	if ((*(t + 8) == 0x24) && (*(t + packet_len - 1) == 0x7c)) {
		t += 8;
		if (memcmp(t, "SR ", 3) == 0)
			return (IPP2P_DC * 100) + 60;
		if (memcmp(t, "Ping ", 5) == 0)
			return (IPP2P_DC * 100) + 61;
	}
	return 0;
}

/*Search for UDP BitTorrent commands*/
static int udp_search_bit(const unsigned char *haystack, int packet_len)
{
	switch (packet_len) {
	case 24:
		/* ^ 00 00 04 17 27 10 19 80 */
		if ((ntohl(get_u32(haystack, 8)) == 0x00000417)
		    && (ntohl(get_u32(haystack, 12)) == 0x27101980))
			return IPP2P_BIT * 100 + 50;
		break;
	case 44:
		if (get_u32(haystack, 16) == __constant_htonl(0x00000400)
		    && get_u32(haystack, 36) == __constant_htonl(0x00000104))
			return IPP2P_BIT * 100 + 51;
		if (get_u32(haystack, 16) == __constant_htonl(0x00000400))
			return IPP2P_BIT * 100 + 61;
		break;
	case 65:
		if (get_u32(haystack, 16) == __constant_htonl(0x00000404)
		    && get_u32(haystack, 36) == __constant_htonl(0x00000104))
			return IPP2P_BIT * 100 + 52;
		if (get_u32(haystack, 16) == __constant_htonl(0x00000404))
			return IPP2P_BIT * 100 + 62;
		break;
	case 67:
		if (get_u32(haystack, 16) == __constant_htonl(0x00000406)
		    && get_u32(haystack, 36) == __constant_htonl(0x00000104))
			return IPP2P_BIT * 100 + 53;
		if (get_u32(haystack, 16) == __constant_htonl(0x00000406))
			return IPP2P_BIT * 100 + 63;
		break;
	case 211:
		if (get_u32(haystack, 8) == __constant_htonl(0x00000405))
			return IPP2P_BIT * 100 + 54;
		break;
	case 29:
		if ((get_u32(haystack, 8) == __constant_htonl(0x00000401)))
			return IPP2P_BIT * 100 + 55;
		break;
	case 52:
		if (get_u32(haystack, 8) == __constant_htonl(0x00000827) &&
		    get_u32(haystack, 12) == __constant_htonl(0x37502950))
			return IPP2P_BIT * 100 + 80;
		break;
	default:
		/* this packet does not have a constant size */
		if (packet_len >= 40
		    && get_u32(haystack, 16) == __constant_htonl(0x00000402)
		    && get_u32(haystack, 36) == __constant_htonl(0x00000104))
			return IPP2P_BIT * 100 + 56;
		break;
	}

	/* some extra-bitcomet rules:
	 * "d1:" [a|r] "d2:id20:"
	 */
	if (packet_len > 30 && get_u8(haystack, 8) == 'd'
	    && get_u8(haystack, 9) == '1' && get_u8(haystack, 10) == ':') {
		if (get_u8(haystack, 11) == 'a' ||
		    get_u8(haystack, 11) == 'r') {
			if (memcmp(haystack + 12, "d2:id20:", 8) == 0)
				return IPP2P_BIT * 100 + 57;
		}
	}

	return 0;
}

/*Search for Ares commands*/
static int search_ares(const unsigned char *payload, const u16 plen)
{
	/* all ares packets start with  */
	if (payload[1] == 0 && (plen - payload[0]) == 3) {
		switch (payload[2]) {
		case 0x5a:
			/* ares connect */
			if (plen == 6 && payload[5] == 0x05)
				return (IPP2P_ARES * 100) + 1;
			break;
		case 0x09:
			/* ares search, min 3 chars --> 14 bytes
			 * lets define a search can be up to
			 *  30 chars --> max 34 bytes
			 */
			if (plen >= 14 && plen <= 34)
				return (IPP2P_ARES * 100) + 1;
			break;
		}
	}

	return 0;
}

/*Search for SoulSeek commands*/
static int search_soul(const unsigned char *payload, const u16 plen)
{
	/* match: xx xx xx xx | xx = sizeof(payload) - 4 */
	if (get_u32(payload, 0) == (plen - 4)) {
		const __u32 m = get_u32(payload, 4);
		/* match 00 yy yy 00, yy can be everything */
		if (get_u8(payload, 4) == 0x00 && get_u8(payload, 7) == 0x00)
			return (IPP2P_SOUL * 100) + 1;

		/* next match: 01 yy 00 00 | yy can be everything */
		if (get_u8(payload, 4) == 0x01 && get_u16(payload, 6) == 0x0000)
			return (IPP2P_SOUL * 100) + 2;

		/* other soulseek commandos are: 1-5,7,9,13-18,22,23,26,
		   28,35-37,40-46,50,51,60,62-69,91,92,1001 */
		/* try to do this in an intelligent way */
		/* get all small commandos */
		switch (m) {
		case 7:
		case 9:
		case 22:
		case 23:
		case 26:
		case 28:
		case 50:
		case 51:
		case 60:
		case 91:
		case 92:
		case 1001:
			return (IPP2P_SOUL * 100) + 3;
		}

		if (m > 0 && m < 6) {
			return (IPP2P_SOUL * 100) + 4;
		}
		if (m > 12 && m < 19) {
			return (IPP2P_SOUL * 100) + 5;
		}

		if (m > 34 && m < 38) {
			return (IPP2P_SOUL * 100) + 6;
		}

		if (m > 39 && m < 47) {
			return (IPP2P_SOUL * 100) + 7;
		}

		if (m > 61 && m < 70) {
			return (IPP2P_SOUL * 100) + 8;
		}

	}

	/* match 14 00 00 00 01 yy 00 00 00 STRING(YY) 01 00 00 00 00 46|50 00 00 00 00 */
	/* without size at the beginning !!! */
	if (get_u32(payload, 0) == 0x14 && get_u8(payload, 4) == 0x01) {
		__u32 y = get_u32(payload, 5);
		/* we need 19 chars + string */
		if ((y + 19) <= (plen)) {
			const unsigned char *w = payload + 9 + y;
			if (get_u32(w, 0) == 0x01
			    && (get_u16(w, 4) == 0x4600
				|| get_u16(w, 4) == 0x5000)
			    && get_u32(w, 6) == 0x00)
			return (IPP2P_SOUL * 100) + 9;
		}
	}
	return 0;
}

/*Search for WinMX commands*/
static int search_winmx(const unsigned char *payload, const u16 plen)
{
	if (((plen) == 4) && (memcmp(payload, "SEND", 4) == 0))
		return (IPP2P_WINMX * 100) + 1;
	if (((plen) == 3) && (memcmp(payload, "GET", 3) == 0))
		return (IPP2P_WINMX * 100) + 2;

	if (plen < 10)
		return 0;

	if ((memcmp(payload, "SEND", 4) == 0)
	    || (memcmp(payload, "GET", 3) == 0)) {
		u16 c = 4;
		const u16 end = plen - 2;
		u8 count = 0;
		while (c < end) {
			if (payload[c] == 0x20 && payload[c + 1] == 0x22) {
				c++;
				count++;
				if (count >= 2)
					return (IPP2P_WINMX * 100) + 3;
			}
			c++;
		}
	}

	if (plen == 149 && payload[0] == '8') {
		if (get_u32(payload, 17) == 0 && get_u32(payload, 21) == 0
		    && get_u32(payload, 25) == 0
		    && get_u16(payload, 39) == 0
		    && get_u16(payload, 135) == htons(0x7edf)
		    && get_u16(payload, 147) == htons(0xf792))
			return (IPP2P_WINMX * 100) + 4;
	}
	return 0;
}

/*Search for appleJuice commands*/
static int search_apple(const unsigned char *payload, const u16 plen)
{
	if ((plen > 7) && (payload[6] == 0x0d) && (payload[7] == 0x0a)
	    && (memcmp(payload, "ajprot", 6) == 0))
		return IPP2P_APPLE * 100;

	return 0;
}

/*Search for BitTorrent commands*/
static int search_bittorrent(const unsigned char *payload, const u16 plen)
{
	if (plen > 20) {
		/* test for match 0x13+"BitTorrent protocol" */
		if (payload[0] == 0x13) {
			if (memcmp(payload + 1, "BitTorrent protocol", 19) == 0)
				return IPP2P_BIT * 100;
		}

		/* get tracker commandos, all starts with GET /
		 * then it can follow: scrape| announce
		 * and then ?hash_info=
		 */
		if (memcmp(payload, "GET /", 5) == 0) {
			/* message scrape */
			if (memcmp(payload + 5, "scrape?info_hash=", 17) == 0)
				return IPP2P_BIT * 100 + 1;
			/* message announce */
			if (memcmp(payload + 5, "announce?info_hash=", 19) == 0)
				return IPP2P_BIT * 100 + 2;
		}
	} else {
		/* bitcomet encryptes the first packet, so we have to detect another
		 * one later in the flow */

		/* second try: block request packets */
		if (plen == 17 && get_u32(payload, 0) == __constant_htonl(0x0d)
		    && payload[4] == 0x06
		    && get_u32(payload, 13) == __constant_htonl(0x4000))
			return IPP2P_BIT * 100 + 3;
	}

	return 0;
}


/*check for gnutella get commands and other typical data*/
static int search_all_gnu(const unsigned char *payload, const u16 plen)
{

	if ((payload[plen - 2] == 0x0d) && (payload[plen - 1] == 0x0a)) {

		if (memcmp(payload, "GNUTELLA CONNECT/", 17) == 0)
			return (IPP2P_GNU * 100) + 1;
		if (memcmp(payload, "GNUTELLA/", 9) == 0)
			return (IPP2P_GNU * 100) + 2;

		if ((memcmp(payload, "GET /get/", 9) == 0)
		    || (memcmp(payload, "GET /uri-res/", 13) == 0)) {
			u16 c = 8;
			const u16 end = plen - 22;
			while (c < end) {
				if (payload[c] == 0x0a && payload[c + 1] == 0x0d
				    &&
				    ((memcmp(&payload[c + 2], "X-Gnutella-", 11)
				      == 0)
				     || (memcmp(&payload[c + 2], "X-Queue:", 8)
					 == 0)))
					return (IPP2P_GNU * 100) + 3;
				c++;
			}
		}
	}
	return 0;
}

/*check for KaZaA download commands and other typical data*/
static int search_all_kazaa(const unsigned char *payload, const u16 plen)
{
	if ((payload[plen - 2] == 0x0d) && (payload[plen - 1] == 0x0a)) {

		if (memcmp(payload, "GIVE ", 5) == 0)
			return (IPP2P_KAZAA * 100) + 1;

		if (memcmp(payload, "GET /", 5) == 0) {
			u16 c = 8;
			const u16 end = plen - 22;
			while (c < end) {
				if (payload[c] == 0x0a && payload[c + 1] == 0x0d
				    &&
				    ((memcmp
				      (&payload[c + 2], "X-Kazaa-Username: ",
				       18) == 0)
				     ||
				     (memcmp
				      (&payload[c + 2],
				       "User-Agent: PeerEnabler/", 24) == 0)))
					return (IPP2P_KAZAA * 100) + 2;
				c++;
			}
		}
	}
	return 0;
}

/*intensive but slower search for some edonkey packets including size-check*/
static int search_all_edk(const unsigned char *payload, const u16 plen)
{
	if (payload[0] != 0xe3)
		return 0;
	else {
		const u16 cmd = get_u16(payload, 1);
		if (cmd == (plen - 5)) {
			switch (payload[5]) {
			case 0x01:
				return (IPP2P_EDK * 100) + 1;	/*Client: hello or Server:hello */
			case 0x4c:
				return (IPP2P_EDK * 100) + 9;	/*Client: Hello-Answer */
			}
		}
		return 0;
	}
}

/*intensive but slower check for all direct connect packets*/
static int search_all_dc(const unsigned char *payload, const u16 plen)
{
	if (payload[0] == 0x24 && payload[plen - 1] == 0x7c) {
		const unsigned char *t = &payload[1];
		/* Client-Hub-Protocol */
		if (memcmp(t, "Lock ", 5) == 0)
			return (IPP2P_DC * 100) + 1;
		/* Client-Client-Protocol, some are already recognized by client-hub (like lock) */
		if (memcmp(t, "MyNick ", 7) == 0)
			return (IPP2P_DC * 100) + 38;
	}
	return 0;
}

/*check for mute*/
static int search_mute(const unsigned char *payload, const u16 plen)
{
	if (plen == 209 || plen == 345 || plen == 473 || plen == 609
	    || plen == 1121) {
		if (memcmp(payload, "PublicKey: ", 11) == 0)
			return (IPP2P_MUTE * 100) + 0;
	}
	return 0;
}

/* check for xdcc */
static int search_xdcc(const unsigned char *payload, const u16 plen)
{
	/* search in small packets only */
	if (plen > 20 && plen < 200 && payload[plen - 1] == 0x0a
	    && payload[plen - 2] == 0x0d
	    && memcmp(payload, "PRIVMSG ", 8) == 0) {

		u16 x = 10;
		const u16 end = plen - 13;

		/* is seems to be a irc private massage, chedck for xdcc command */
		while (x < end) {
			if (payload[x] == ':') {
				if (memcmp(&payload[x + 1], "xdcc send #", 11)
				    == 0)
					return (IPP2P_XDCC * 100) + 0;
			}
			x++;
		}
	}
	return 0;
}

/* search for waste */
static int search_waste(const unsigned char *payload, const u16 plen)
{
	if (plen >= 8 && memcmp(payload, "GET.sha1:", 9) == 0)
		return IPP2P_WASTE * 100 + 0;

	return 0;
}

static const struct tcp_match {
	int command;
	__u8 short_hand;	/*for functions included in short hands */
	u16 packet_len;
	int (*function_name) (const unsigned char *, const u16);
} matchlist[] = {
	{ IPP2P_EDK, SHORT_HAND_IPP2P, 20, &search_all_edk },
	{ IPP2P_DC, SHORT_HAND_IPP2P, 5, search_all_dc },
	{ IPP2P_GNU, SHORT_HAND_IPP2P, 5, &search_all_gnu },
	{ IPP2P_KAZAA, SHORT_HAND_IPP2P, 5, &search_all_kazaa },
	{ IPP2P_BIT, SHORT_HAND_IPP2P, 20, &search_bittorrent },
	{ IPP2P_APPLE, SHORT_HAND_IPP2P, 5, &search_apple },
	{ IPP2P_SOUL, SHORT_HAND_IPP2P, 5, &search_soul },
	{ IPP2P_WINMX, SHORT_HAND_IPP2P, 2, &search_winmx },
	{ IPP2P_ARES, SHORT_HAND_IPP2P, 5, &search_ares },
	{ IPP2P_MUTE, SHORT_HAND_NONE, 200, &search_mute },
	{ IPP2P_WASTE, SHORT_HAND_NONE, 5, &search_waste },
	{ IPP2P_XDCC, SHORT_HAND_NONE, 5, &search_xdcc },
	{ 0 }
};

static bool match_tcp(const struct sk_buff *skb, unsigned len,
		      const struct ipt_p2p_info *info)
{
	const struct tcphdr *tcph = tcp_hdr(skb);
	const struct tcp_match *mp;
	const u8 *haystack;

	if (len < tcp_hdrlen(skb))
		return false;

	if (tcph->fin | tcph->syn | tcph->rst)
		return false;

	len -= tcp_hdrlen(skb);
	haystack = (const u8 *) tcph + tcp_hdrlen(skb);

	for (mp = matchlist; mp->command; ++mp) {
		if ((((info->cmd & mp->command) == mp->command) ||
		     ((info->cmd & mp->short_hand) == mp->short_hand)) &&
		    len > mp->packet_len) {
			int result = mp->function_name(haystack, len);
			if (!result)
				continue;
			if (info->debug) {
				const struct iphdr *ip = ip_hdr(skb);
				printk(KERN_DEBUG
				       "IPP2P.debug:TCP-match: from: %pM:%i to: %pM:%i Length: %i\n",
				       &ip->saddr, ntohs(tcph->source),
				       &ip->daddr, ntohs(tcph->dest), len);
			}

			return true;
		}
	}

	return false;
}

static const struct udp_match {
	int command;
	__u8 short_hand;	/*for functions included in short hands */
	u16 packet_len;
	int (*function_name) (const unsigned char *, int);
} udp_list[] = {
	{ IPP2P_KAZAA, SHORT_HAND_IPP2P, 14, &udp_search_kazaa },
	{ IPP2P_BIT, SHORT_HAND_IPP2P, 23, &udp_search_bit },
	{ IPP2P_GNU, SHORT_HAND_IPP2P, 11, &udp_search_gnu },
	{ IPP2P_EDK, SHORT_HAND_IPP2P, 9, &udp_search_edk },
	{ IPP2P_DC, SHORT_HAND_IPP2P, 12, &udp_search_directconnect },
	{ 0 }
};

static bool match_udp(const struct sk_buff *skb, unsigned len,
		      const struct ipt_p2p_info *info)
{
	struct udphdr *udph = udp_hdr(skb);
	const struct udp_match *up;
	const u8 *haystack;

	if (len < sizeof(struct udphdr))
		return false;

	len -= sizeof(struct udphdr);
	haystack = (const u8 *) (udph + 1);

	for (up = udp_list; up->command; up++) {
		if (((info->cmd & up->command) == up->command ||
		     ((info->cmd & up->short_hand) == up->short_hand)) &&
		    len > up->packet_len) {
			int result = up->function_name(haystack, len);
			if (!result)
				continue;

			if (info->debug) {
				const struct iphdr *ip = ip_hdr(skb);
				printk(KERN_DEBUG
				       "IPP2P.debug:UDP-match: from: %pM:%i to: %pM:%i Length: %i\n",
				       &ip->saddr, ntohs(udph->source),
				       &ip->daddr, ntohs(udph->dest), len);
			}
			return true;
		}
	}
	return false;
}

static bool match(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct iphdr *ip;
	unsigned len;

	if (par->fragoff)
		return false;

	/* make sure that skb is linear */
	if (skb_is_nonlinear(skb)) {
		pr_debug("IPP2P.match: nonlinear skb found\n");
		return false;
	}

	ip = ip_hdr(skb);
	if (skb->len < sizeof(struct iphdr))
		return false;

	len = ntohs(ip->tot_len) - ip->ihl*4;

	switch (ip->protocol) {
	case IPPROTO_TCP:
		return match_tcp(skb, len, par->matchinfo);

	case IPPROTO_UDP:
		return match_udp(skb, len, par->matchinfo);

	default:
		return false;
	}
}

static struct xt_match ipp2p_match __read_mostly = {
	.name = "ipp2p",
	.family = NFPROTO_IPV4,
	.match = match,
	.matchsize = sizeof(struct ipt_p2p_info),
	.me = THIS_MODULE
};

static int __init init(void)
{
	printk(KERN_INFO "IPP2P v%s loading\n", IPP2P_VERSION);
	return xt_register_match(&ipp2p_match);
}

static void __exit fini(void)
{
	xt_unregister_match(&ipp2p_match);
}

module_init(init);
module_exit(fini);
