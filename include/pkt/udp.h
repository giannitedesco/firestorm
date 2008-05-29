#ifndef _PKT_UDP_HEADER_INCLUDED_
#define _PKT_UDP_HEADER_INCLUDED_

struct pkt_udphdr {
	uint16_t	sport,dport;
	uint16_t	len;
	uint16_t	csum;
} _packed;

#endif /* _PKT_UDP_HEADER_INCLUDED_ */
