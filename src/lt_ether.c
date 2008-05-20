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

#define DLT_EN10MB 1

static void eth_decode(struct _pkt *p);

static struct _decoder decoder = {
	.d_label = "Ethernet",
	.d_decode = eth_decode,
};

static struct _proto p_eth = {
	.p_label = "Ethernet II",
	.p_namespace = NS_ETHER,
};

static struct _proto p_802 = {
	.p_label = "802.3",
	.p_namespace = NS_ETHER,
};

static struct _proto p_nw = {
	.p_label = "802.3-netware",
	.p_namespace = NS_ETHER,
};

static struct _proto p_vlan = {
	.p_label = "802.1q",
	.p_namespace = NS_ETHER,
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&decoder);
	decoder_register(&decoder, NS_DLT, DLT_EN10MB);
	proto_add(&decoder, &p_eth);
	proto_add(&decoder, &p_802);
	proto_add(&decoder, &p_nw);
	proto_add(&decoder, &p_vlan);
}

static void netware_decode(struct _pkt *p)
{
	mesg(M_DEBUG, "802.3-netware");
}

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
	
	_decode_next(p, &p_vlan, vlan->proto);
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
		if ( (p->pkt_nxthdr + 2 <= p->pkt_end) &&
			*(uint16_t *)p->pkt_nxthdr == 0xffff ) {
			netware_decode(p);
		}else{
			mac_decode(p);
		}
		return;
	case 0x8100:
		vlan_decode(p);
		return;
	default:
		break;
	}

	mesg(M_DEBUG, "ethernet II - 0x%.4x", proto);
	_decode_next(p, &p_eth, eth->proto);
}
