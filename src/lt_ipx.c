/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <pkt/ipx.h>

static struct _decoder ipx_decoder = {
	.d_label = "IPX",
	.d_decode = _ipx_decode,
};

static struct _proto p_nw = {
	.p_label = "ipx",
	.p_namespace = NS_IPX,
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&ipx_decoder);
	decoder_register(&ipx_decoder, NS_ETHER, const_be16(0x8137));
	proto_add(&ipx_decoder, &p_nw);
}

void _ipx_decode(struct _pkt *p)
{
	const struct pkt_ipxhdr *ipxh;

	ipxh = (const struct pkt_ipxhdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*ipxh);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	mesg(M_DEBUG, "IPX type = 0x%.2x", ipxh->type);
}
