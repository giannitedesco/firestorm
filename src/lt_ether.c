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

/* TODO: arp: NS_ETHER / 0x0806 */

static struct _decoder eth_decoder = {
	.d_label = "Ethernet",
	.d_decode = _eth_decode,
};

static struct _proto p_eth = {
	.p_label = "ether",
};

static struct _proto p_llc = {
	.p_label = "snap",
};

static struct _proto p_snap = {
	.p_label = "llc",
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&eth_decoder);
	decoder_register(&eth_decoder, NS_DLT, DLT_EN10MB);
	proto_add(&eth_decoder, &p_eth);
	proto_add(&eth_decoder, &p_llc);
	proto_add(&eth_decoder, &p_snap);
}

static void snap_decode(struct _pkt *p)
{
	const struct pkt_snaphdr *snap;
	proto_id_t org;

	snap = (const struct pkt_snaphdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*snap);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	org = (snap->org[0] << 12) | (snap->org[1] << 8) | snap->org[2];
	switch(org) {
	case SNAP_ORG_ETHER:
		mesg(M_DEBUG, "802.3: SNAP: Ethernet 0x%.4x",
			sys_be16(snap->proto));
		/* XXX: Don't look for a length instead of a protocol */
		_decode_next(p, NS_ETHER, snap->proto);
		break;
	case SNAP_ORG_APPLE:
		mesg(M_DEBUG, "802.3: SNAP: Apple 0x%.4x",
			sys_be16(snap->proto));
		_decode_next(p, NS_APPLE, snap->proto);
		break;
	case SNAP_ORG_CISCO:
		mesg(M_DEBUG, "802.3: SNAP: Cisco 0x%.4x",
			sys_be16(snap->proto));
		_decode_next(p, NS_CISCO, snap->proto);
		break;
	default:
		mesg(M_WARN, "802.3: SNAP: unknown org=0x%x (0x%.4x)",
			org, sys_be16(snap->proto));
		break;
	}

	return;
}

static void mac_decode(struct _pkt *p)
{
	const struct pkt_llchdr *llc;

	llc = (const struct pkt_llchdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*llc);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	if ( llc->dsap == 0xaa &&
		llc->lsap == 0xaa && llc->ctrl == 0x3 ) {
		snap_decode(p);
		return;
	}

	switch(llc->lsap) {
	case 0xe0: /* ipx */
		break;
	case 0xf0: /* netbios */
		break;
	case 0x42: /* stp */
		break;
	}

	mesg(M_DEBUG, "802.3: LLC dsap = %.2x, lsap = %.2x",
		llc->dsap, llc->lsap);
}

static void vlan_decode(struct _pkt *p)
{
	const struct pkt_vlanhdr *vlan;
	uint16_t proto;

	vlan = (const struct pkt_vlanhdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*vlan);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	proto = sys_be16(vlan->proto);
	mesg(M_DEBUG, "802.1q proto = 0x%.4x", proto);

	/* protocols can still be lengths with 802.1q */
	switch(proto) {
	case 0 ... 1500:
		mac_decode(p);
		return;
	default:
		break;
	}

	_decode_next(p, NS_ETHER, vlan->proto);
}

void _eth_decode(struct _pkt *p)
{
	const struct pkt_ethhdr *eth;
	uint16_t proto;

	eth = (const struct pkt_ethhdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*eth);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	proto = sys_be16(eth->proto);

	/* Check if it's a length or a protocol */
	switch(proto) {
	case 0 ... 1500:
		mac_decode(p);
		return;
	case 0x8100:
		vlan_decode(p);
		return;
	default:
		break;
	}

	mesg(M_DEBUG, "ethernet II - 0x%.4x", proto);
	_decode_next(p, NS_ETHER, eth->proto);
}
