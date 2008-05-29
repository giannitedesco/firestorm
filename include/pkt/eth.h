#ifndef _PKT_ETH_HEADER_INCLUDED_
#define _PKT_ETH_HEADER_INCLUDED_

#define SNAP_ORG_APPLE 0x8007
#define SNAP_ORG_CISCO 0xc
#define SNAP_ORG_ETHER 0x0

/* Ethernet II */
struct pkt_ethhdr {
	uint8_t		dst[6];
	uint8_t		src[6];
	uint16_t	proto;
} _packed;

/* 802.3 MAC header */
struct pkt_machdr {
	uint8_t		dst[6];
	uint8_t		src[6];
	uint16_t	len;
} _packed;

/* 802.2 Logical Link control */
struct pkt_llchdr {
	uint8_t		dsap,lsap;
	uint8_t		ctrl;
} _packed;

/* Sub-Network Access protocol */
/* XXX: Packed to stop gcc padding the 3 byte array to 4 bytes */
struct pkt_snaphdr {
	uint8_t		org[3];
	uint16_t	proto;
} _packed;

void _eth_decode(struct _pkt *p);

#endif /* _PKT_ETH_HEADER_INCLUDED_ */
