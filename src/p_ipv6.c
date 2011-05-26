/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>
#include <pkt/ipv6.h>

static void ipv6_decode(struct _pkt *p);

static struct _decoder decoder = {
	.d_label = "IPv4",
	.d_decode = ipv6_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&decoder);
	decoder_register(&decoder, NS_ETHER, const_be16(0x86dd));
	decoder_register(&decoder, NS_UNIXPF, 28);
}

static void ipv6_decode(struct _pkt *p)
{
	struct pkt_ip6hdr *iph;
	uint16_t len;

	iph = (struct pkt_ip6hdr *)p->pkt_nxthdr;

	p->pkt_nxthdr += sizeof(*iph);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	len = be16toh(iph->ip6_plen);
	p->pkt_nxthdr += len;
	if ( p->pkt_nxthdr > p->pkt_end ) {
		mesg(M_WARN, "truncated IP packet");
		return;
	}

	switch(iph->ip6_proto) {
	case IP6_PROTO_HOPBYHOP:
		break;
	case IP6_PROTO_TCP:
		break;
	case IP6_PROTO_UDP:
		break;
	case IP6_PROTO_ICMP:
		break;
	case IP6_PROTO_PIM:
		break;
	default:
		mesg(M_DEBUG, "IPv6 proto = 0x%.2x, len = %u",
			iph->ip6_proto, len);
	}
}
