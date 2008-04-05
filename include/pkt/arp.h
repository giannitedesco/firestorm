#ifndef __PKT_ARP_HEADER_INCLUDED__
#define __PKT_ARP_HEADER_INCLUDED__

struct pkt_arphdr {
	uint16_t	hrd;
	uint16_t	proto;
	uint8_t		hln;
	uint8_t		pln;
	uint16_t	op;
};

#define ARP_OP_REQUEST		0x1
#define ARP_OP_REPLY		0x2

#define FLAG_ARP_SENDER		0x1
#define FLAG_ARP_TARGET		0x2

#endif /* __PKT_ARP_HEADER_INCLUDED__ */
