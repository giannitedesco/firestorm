/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_capture.h>
#include <f_decode.h>
#include <p_arp.h>

#include <pkt/eth.h>
#include <pkt/ip.h>
#include <pkt/arp.h>

#if 0
#define dmesg mesg
#else
#define dmesg(x...) do{}while(0);
#endif

static void arp_decode(struct _pkt *p);

static struct _proto p_arp = {
	.p_label = "arp",
	.p_dcb_sz = sizeof(struct arp_dcb),
};

static struct _decoder decoder = {
	.d_label = "ARP",
	.d_decode = arp_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&decoder);
	decoder_register(&decoder, NS_ETHER, const_be16(0x806));
	proto_add(&decoder, &p_arp);
}

static void arp_decode(struct _pkt *p)
{
	const struct pkt_arphdr *arp;
	const uint8_t *sha;
	const uint8_t *spa;
	const uint8_t *tha;
	const uint8_t *tpa;
	struct arp_dcb *dcb;

	arp = (const struct pkt_arphdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*arp);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	sha = p->pkt_nxthdr;
	p->pkt_nxthdr += arp->hlen;
	spa = p->pkt_nxthdr;
	p->pkt_nxthdr += arp->plen;
	tha = p->pkt_nxthdr;
	p->pkt_nxthdr += arp->hlen;
	tpa = p->pkt_nxthdr;
	p->pkt_nxthdr += arp->plen;
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	switch(sys_be16(arp->op)) {
	case ARP_OP_REQUEST:
		dmesg(M_DEBUG, "ARP request");
		break;
	case ARP_OP_REPLY:
		dmesg(M_DEBUG, "ARP reply");
		break;
	default:
		dmesg(M_WARN, "Unknown ARP op (0x%.4x)",
			sys_be16(arp->op));
		break;
	}

	dcb = (struct arp_dcb *) _decode_layer(p, &p_arp);
	if ( dcb == NULL ) {
		dcb->arp_hdr = arp;
		dcb->arp_sha = sha;
		dcb->arp_spa = spa;
		dcb->arp_tha = tha;
		dcb->arp_tpa = tpa;
	}
}
