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

#if 0
#define dmesg mesg
#else
#define dmesg(x...) do{}while(0);
#endif

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

static void snap_decode(struct _pkt *p, const struct pkt_ethhdr *eth,
			const struct pkt_vlanhdr *vlan,
			const struct pkt_llchdr *llc)
{
	const struct pkt_snaphdr *snap;
	proto_id_t org;

	snap = (const struct pkt_snaphdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*snap);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	org = (snap->org[0] << 12) | (snap->org[1] << 8) | snap->org[2];
	_decode_layer(p, &p_snap);

	switch(org) {
	case SNAP_ORG_ETHER:
		dmesg(M_DEBUG, "802.3: SNAP: Ethernet 0x%.4x",
			sys_be16(snap->proto));
		/* XXX: Don't look for a length instead of a protocol */
		_decode_next(p, NS_ETHER, snap->proto);
		break;
	case SNAP_ORG_APPLE:
		dmesg(M_DEBUG, "802.3: SNAP: Apple 0x%.4x",
			sys_be16(snap->proto));
		_decode_next(p, NS_APPLE, snap->proto);
		break;
	case SNAP_ORG_CISCO:
		dmesg(M_DEBUG, "802.3: SNAP: Cisco 0x%.4x",
			sys_be16(snap->proto));
		_decode_next(p, NS_CISCO, snap->proto);
		break;
	default:
		dmesg(M_WARN, "802.3: SNAP: unknown org=0x%x (0x%.4x)",
			org, sys_be16(snap->proto));
		break;
	}
}

static void llc_decode(struct _pkt *p, const struct pkt_ethhdr *eth,
			const struct pkt_vlanhdr *vlan)
{
	const struct pkt_llchdr *llc;

	llc = (const struct pkt_llchdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*llc);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	if ( llc->dsap == 0xaa &&
		llc->lsap == 0xaa && llc->ctrl == 0x3 ) {
		snap_decode(p, eth, vlan, llc);
		return;
	}

	switch(llc->lsap) {
	case 0xe0: /* ipx */
	case 0xf0: /* netbios */
	case 0x42: /* stp */
	default:
		_decode_layer(p, &p_llc);
		dmesg(M_DEBUG, "802.3: LLC dsap = %.2x, lsap = %.2x",
			llc->dsap, llc->lsap);
		break;
	}
}

static void vlan_decode(struct _pkt *p, const struct pkt_ethhdr *eth)
{
	const struct pkt_vlanhdr *vlan;
	uint16_t proto;

	vlan = (const struct pkt_vlanhdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*vlan);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	proto = sys_be16(vlan->proto);
	/* protocols can still be lengths with 802.1q */
	switch(proto) {
	case 0 ... 1500:
		llc_decode(p, eth, vlan);
		return;
	default:
		dmesg(M_DEBUG, "802.1q proto = 0x%.4x", proto);
		_decode_layer(p, &p_eth);
		_decode_next(p, NS_ETHER, vlan->proto);
		break;
	}
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
		llc_decode(p, eth, NULL);
		break;
	case 0x8100:
		vlan_decode(p, eth);
		break;
	default:
		dmesg(M_DEBUG, "ethernet II - 0x%.4x", proto);
		_decode_layer(p, &p_eth);
		_decode_next(p, NS_ETHER, eth->proto);
		break;
	}
}
