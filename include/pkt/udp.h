#ifndef __PKT_UDP_HEADER_INCLUDED__
#define __PKT_UDP_HEADER_INCLUDED__

struct pkt_udphdr {
	uint16_t	sport,dport;
	uint16_t	len;
	uint16_t	csum;
};

#endif /* __PKT_UDP_HEADER_INCLUDED__ */
