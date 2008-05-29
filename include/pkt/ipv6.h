#ifndef __PKT_IPV6_HEADER_INCLUDED__
#define __PKT_IPV6_HEADER_INCLUDED__

struct ip6_addr {
	union {
		uint8_t addr[16];
		uint16_t addr16[8];
		uint32_t addr32[4];
		uint64_t addr64[2];
	}ip6_u;
} _packed;

struct pkt_ip6hdr {
	uint32_t ip6_flowlabel;
	uint16_t ip6_plen;
	uint8_t ip6_proto;
	uint8_t ip6_ttl;
	struct ip6_addr ip6_src, ip6_dst;
} _packed;

#endif /* __PKT_IPV6_HEADER_INCLUDED__ */
