/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>
#include <pkt/ip.h>

#include <sys/socket.h>

static void ipv4_decode(struct _pkt *p);

static struct _decoder decoder = {
	.d_label = "IPv4",
	.d_decode = ipv4_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&decoder);
	decoder_register(&decoder, NS_ETHER, const_be16(0x0800));
	decoder_register(&decoder, NS_UNIXPF, PF_INET);
}

static void ipv4_decode(struct _pkt *p)
{
	struct pkt_iphdr *iph;

	iph = (struct pkt_iphdr *)p->pkt_nxthdr;

	p->pkt_nxthdr += sizeof(*iph);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	mesg(M_DEBUG, "IPv4 proto = 0x%.2x", iph->protocol);
}
