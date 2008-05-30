/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_capture.h>
#include <f_decode.h>

#include <pkt/sll.h>
#include <pkt/eth.h>
#include <pkt/ipx.h>

static void sll_decode(struct _pkt *p);

static struct _proto p_sll = {
	.p_label = "sll",
};

static struct _decoder decoder = {
	.d_label = "Linux Cooked",
	.d_decode = sll_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&decoder);
	decoder_register(&decoder, NS_DLT, 0x71);
	proto_add(&decoder, &p_sll);
}

static void sll_decode(struct _pkt *p)
{
	const struct pkt_sllhdr *sll;
	uint16_t proto;

	sll = (const struct pkt_sllhdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*sll);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	proto = source_n16(p->pkt_source, sll->sll_protocol);

	mesg(M_DEBUG, "Linux: type=0x%.4x, hatype=0x%.4x, proto=0x%.4x",
		source_h16(p->pkt_source, sll->sll_pkttype),
		source_h16(p->pkt_source, sll->sll_hatype),
		source_h16(p->pkt_source, sll->sll_protocol));

	_decode_layer(p, &p_sll);

	switch(proto) {
	case const_be16(LINUX_SLL_P_802_3):
		_ipx_decode(p);
		break;
	case const_be16(LINUX_SLL_P_802_2):
		_eth_decode(p);
		break;
	case const_be16(LINUX_SLL_P_PPPHDLC):
		break;
	default:
		_decode_next(p, NS_ETHER, proto);
	}
}
