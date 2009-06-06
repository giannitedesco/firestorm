#ifndef _PKT_ARP_HEADER_INCLUDED_
#define _PKT_ARP_HEADER_INCLUDED_

struct pkt_arphdr {
	uint16_t	hrd;
	uint16_t	proto;
	uint8_t		hlen;
	uint8_t		plen;
	uint16_t	op;
} _packed;

#define ARP_OP_REQUEST		0x1
#define ARP_OP_REPLY		0x2

#endif /* _PKT_ARP_HEADER_INCLUDED_ */
