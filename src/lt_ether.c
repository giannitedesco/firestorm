/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <pkt/eth.h>
#include <pkt/vlan.h>

static void mac_decode(struct _pkt *p)
{
	const struct pkt_machdr *mac;
	const struct pkt_llchdr *llc;
	(void)mac;
	(void)llc;
	mesg(M_DEBUG, "802.3");
}

static void vlan_decode(struct _pkt *p)
{
	const struct pkt_vlanhdr *vlan;

	vlan = (const struct pkt_vlanhdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*vlan);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	mesg(M_DEBUG, "vlan id = 0x%.4x, proto = 0x%.4x",
		sys_be16(vlan->vlan), sys_be16(vlan->proto));
}

static void eth_decode(struct _pkt *p)
{
	const struct pkt_ethhdr *eth;
	uint16_t proto;

	eth = (const struct pkt_ethhdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*eth);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	proto = sys_be16(eth->proto);

	switch(proto) {
	case 64 ... 1500:
		mac_decode(p);
		return;
	case 0x8100:
		vlan_decode(p);
		return;
	default:
		break;
	}

	mesg(M_DEBUG, "ethernet II - 0x%.4x", proto);
	//hex_dump(p->pkt_base, p->pkt_caplen, 16);
}

#define DLT_EN10MB 1

static struct _netproto proto = {
	.np_id = DLT_EN10MB,
	.np_label = "Ethernet II",
	.np_decode = eth_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	netproto_register(&proto);
}
