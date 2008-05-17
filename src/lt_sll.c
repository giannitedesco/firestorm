/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_capture.h>
#include <f_decode.h>

struct linux_sll {
	uint16_t	sll_pkttype;
	uint16_t	sll_hatype;
	uint16_t	sll_halen;
	uint8_t		sll_addr[8];
	uint16_t	sll_proto;
};

static void sll_decode(struct _pkt *p)
{
	const struct linux_sll *sll;

	sll = (const struct linux_sll *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*sll);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	mesg(M_DEBUG, "Linux packet 0x%.4x",
		source_swap16(p->pkt_source, sll->sll_proto));
}

static struct _linktype lt = {
	.lt_id = 0x71,
	.lt_label = "Linux Cooked (SLL)",
	.lt_decode = sll_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	linktype_register(&lt);
}
