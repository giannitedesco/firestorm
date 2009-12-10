/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _P_IPV4_HEADER_INCLUDED_
#define _P_IPV4_HEADER_INCLUDED_

struct ipfrag_dcb {
	struct _dcb ip_dcb;
	const struct pkt_iphdr *ip_iph;
};

struct ip_dcb {
	struct _dcb ip_dcb;
	const struct pkt_iphdr *ip_iph;
	const struct pkt_ahhdr *ip_ah;
};

struct tcp_dcb {
	struct _dcb tcp_dcb;
	const struct pkt_iphdr *tcp_iph;
	const struct pkt_ahhdr *tcp_ah;
	const struct pkt_tcphdr *tcp_hdr;
	struct tcp_session *tcp_sess;
};

struct udp_dcb {
	struct _dcb udp_dcb;
	const struct pkt_iphdr *udp_iph;
	const struct pkt_ahhdr *udp_ah;
	const struct pkt_udphdr *udp_hdr;
};

struct icmp_dcb {
	struct _dcb icmp_dcb;
	const struct pkt_iphdr *icmp_iph;
	const struct pkt_ahhdr *icmp_ah;
	const struct pkt_icmphdr *icmp_hdr;
	const struct pkt_iphdr *icmp_inner;
};

/* sizeof("255.255.255.255\0") */
#define IPSTR_SZ 16
typedef char ipstr_t[IPSTR_SZ];
void iptostr(ipstr_t str, uint32_t ip);

uint16_t _ip_csum(const struct pkt_iphdr *iph);

#endif /* _P_IPV4_HEADER_INCLUDED_ */
