#ifndef __PKT_IGMP_HEADER_INCLUDED__
#define __PKT_IGMP_HEADER_INCLUDED__

struct pkt_igmphdr {
	uint8_t		type;
	uint8_t		code;
	uint16_t	csum;
	uint32_t	group;
} _packed;

#endif /* __PKT_IGMP_HEADER_INCLUDED__ */
