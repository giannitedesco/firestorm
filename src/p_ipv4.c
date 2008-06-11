/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_flow.h>
#include <pkt/ip.h>
#include <pkt/icmp.h>
#include <pkt/tcp.h>
#include <pkt/udp.h>
#include "p_ipv4.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if 0
#define dmesg mesg
#else
#define dmesg(x...) do{}while(0);
#endif

static const uint16_t ipfmask = const_be16(IP_MF|IP_OFFMASK);

static void ipv4_decode(struct _pkt *p);
static void ah_decode(struct _pkt *p, const struct pkt_iphdr *iph,
			const struct pkt_ahhdr *bogus);

static struct _proto p_fragment = {
	.p_label = "ipfrag",
	.p_dcb_sz = sizeof(struct ipfrag_dcb),
};

static struct _proto p_ipraw = {
	.p_label = "ipraw",
	.p_dcb_sz = sizeof(struct ip_dcb),
};

static struct _proto p_tunnel = {
	.p_label = "iptunnel",
	.p_dcb_sz = sizeof(struct ip_dcb),
};

static struct _proto p_icmp = {
	.p_label = "icmp",
	.p_dcb_sz = sizeof(struct icmp_dcb),
};

static struct _proto p_igmp = {
	.p_label = "igmp",
};

static struct _proto p_sctp = {
	.p_label = "sctp",
};

static struct _proto p_dccp = {
	.p_label = "dccp",
};

static struct _proto p_esp = {
	.p_label = "esp",
};

static struct _proto p_tcp = {
	.p_label = "tcp",
	.p_dcb_sz = sizeof(struct tcp_dcb),
};

static struct _proto p_udp = {
	.p_label = "udp",
	.p_dcb_sz = sizeof(struct udp_dcb),
};

struct _decoder _ipv4_decoder = {
	.d_label = "IPv4",
	.d_decode = ipv4_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&_ipv4_decoder);
	decoder_register(&_ipv4_decoder, NS_ETHER, const_be16(0x0800));
	decoder_register(&_ipv4_decoder, NS_UNIXPF, 2);
	proto_add(&_ipv4_decoder, &p_fragment);
	proto_add(&_ipv4_decoder, &p_tunnel);
	proto_add(&_ipv4_decoder, &p_ipraw);
	proto_add(&_ipv4_decoder, &p_icmp);
	proto_add(&_ipv4_decoder, &p_igmp);
	proto_add(&_ipv4_decoder, &p_sctp);
	proto_add(&_ipv4_decoder, &p_dccp);
	proto_add(&_ipv4_decoder, &p_tcp);
	proto_add(&_ipv4_decoder, &p_udp);
	proto_add(&_ipv4_decoder, &p_esp);
	flow_tracker_add(&p_fragment, &_ipv4_ipdefrag);
	flow_tracker_add(&p_tcp, &_ipv4_tcpflow);
}

void iptostr(ipstr_t str, uint32_t ip)
{
	struct in_addr in;
	in.s_addr = ip;
	strncpy(str, inet_ntoa(in), IPSTR_SZ);
}

uint16_t _ip_csum(const struct pkt_iphdr *iph)
{
	uint16_t *tmp = (uint16_t *)iph;
	uint32_t sum = 0;
	int i;

	for(i=0; i < (iph->ihl << 1); i++) {
		sum += tmp[i];
		if(sum & 0x80000000)
			sum = (sum & 0xffff) + (sum >> 16);
	}

	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum & 0xffff;
}

static void raw_decode(struct _pkt *p, const struct pkt_iphdr *iph,
			const struct pkt_ahhdr *ah)
{
	struct ip_dcb *dcb;
	dcb = (struct ip_dcb *)_decode_layer(p, &p_ipraw);
	if ( dcb ) {
		dcb->ip_iph = iph;
		dcb->ip_ah = ah;
	}

	dmesg(M_WARN, "ipv4: unknown protocol %u", iph->protocol);
}

static void tunnel_decode(struct _pkt *p, const struct pkt_iphdr *iph,
			const struct pkt_ahhdr *ah)
{
	struct ip_dcb *dcb;

	dcb = (struct ip_dcb *)_decode_layer(p, &p_tunnel);
	if ( dcb ) {
		dcb->ip_iph = iph;
		dcb->ip_ah = ah;
	}

	dmesg(M_INFO, "ipv4: tunnel");
	ipv4_decode(p);
}

static void icmp_decode(struct _pkt *p, const struct pkt_iphdr *iph,
			const struct pkt_ahhdr *ah)
{
	const struct pkt_icmphdr *icmph;
	struct icmp_dcb *dcb;

	icmph = (const struct pkt_icmphdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*icmph);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	dmesg(M_DEBUG, "ipv4: tcp type=%u code=%u",
		icmph->type, icmph->code);

	dcb = (struct icmp_dcb *)_decode_layer(p, &p_icmp);
	if ( dcb ) {
		dcb->icmp_iph = iph;
		dcb->icmp_ah = ah;
		dcb->icmp_hdr = icmph;
	}
}

static void tcp_decode(struct _pkt *p, const struct pkt_iphdr *iph,
			const struct pkt_ahhdr *ah)
{
	const struct pkt_tcphdr *tcph;
	struct tcp_dcb *dcb;

	if ( p->pkt_nxthdr + sizeof(*tcph) > p->pkt_end )
		return;

	tcph = (const struct pkt_tcphdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += tcph->doff << 2;
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	dmesg(M_DEBUG, "ipv4: tcp %u -> %u",
		sys_be16(tcph->sport), sys_be16(tcph->dport));

	dcb = (struct tcp_dcb *)_decode_layer(p, &p_tcp);
	if ( dcb ) {
		dcb->tcp_iph = iph;
		dcb->tcp_ah = ah;
		dcb->tcp_hdr = tcph;
	}
}

static void udp_decode(struct _pkt *p, const struct pkt_iphdr *iph,
			const struct pkt_ahhdr *ah)
{
	const struct pkt_udphdr *udph;
	struct udp_dcb *dcb;

	udph = (const struct pkt_udphdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*udph);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	dmesg(M_DEBUG, "ipv4: udp %u -> %u",
		sys_be16(udph->sport), sys_be16(udph->dport));

	dcb = (struct udp_dcb *)_decode_layer(p, &p_udp);
	if ( dcb ) {
		dcb->udp_iph = iph;
		dcb->udp_ah = ah;
		dcb->udp_hdr = (void *)p->pkt_nxthdr;
	}
}

static void esp_decode(struct _pkt *p, const struct pkt_iphdr *iph,
			const struct pkt_ahhdr *ah)
{
	const struct pkt_esphdr *esp;

	esp = (const struct pkt_esphdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*esp);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	dmesg(M_DEBUG, "ipv4: ESP spi=0x%.8x", sys_be32(esp->spi));
	_decode_layer(p, &p_esp);
}

typedef void (*ipproto_t)(struct _pkt *p, const struct pkt_iphdr *iph,
				const struct pkt_ahhdr *ah);

static const ipproto_t subproto[] = {
	raw_decode,
	icmp_decode,
	NULL, /* reserved for igmp */
	tunnel_decode,
	tcp_decode,
	udp_decode,
	NULL, /* reserved for dccp */
	esp_decode,
	ah_decode,
	NULL, /* reserved for sctp */
};

static const uint8_t pmap[0x100] = {
	[IP_PROTO_ICMP] 1,
	[IP_PROTO_IGMP] 0,
	[IP_PROTO_IPIP] 3,
	[IP_PROTO_TCP] 4,
	[IP_PROTO_UDP] 5,
	[IP_PROTO_DCCP] 0,
	[IP_PROTO_ESP] 7,
	[IP_PROTO_AH] 8,
	[IP_PROTO_SCTP] 0,
};

static void ah_decode(struct _pkt *p, const struct pkt_iphdr *iph,
			const struct pkt_ahhdr *bogus)
{
	const struct pkt_ahhdr *ah;

	if ( unlikely(bogus) ) {
		mesg(M_WARN, "ipv4(ah): nesting AH...");
		return;
	}

	ah = (struct pkt_ahhdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*ah);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	if ( ah->ahl < 4 ) {
		mesg(M_WARN, "ipv4(ah): header length %u < %u",
			ah->ahl << 2, sizeof(*ah));
		return;
	}

	p->pkt_nxthdr += (ah->ahl << 2) - 2;
	if ( p->pkt_nxthdr > p->pkt_end ) {
		mesg(M_WARN, "ipv4(ah): Truncated AH packet");
		return;
	}

	dmesg(M_DEBUG, "AH spi=0x%.8x", sys_be32(ah->spi));

	(*subproto[pmap[ah->protocol]])(p, iph, ah);
}

static void ipv4_decode(struct _pkt *p)
{
	const struct pkt_iphdr *iph;
	uint16_t len;

	iph = (struct pkt_iphdr *)p->pkt_nxthdr;

	if ( p->pkt_nxthdr + sizeof(*iph) > p->pkt_end )
		return;

	if ( iph->ihl < 5 ) {
		mesg(M_WARN, "ipv4: header length %u < %u",
			iph->ihl << 2, sizeof(*iph));
		return;
	}

	if ( iph->version != 4 ) {
		mesg(M_WARN, "ipv4: bad version %u != 4", iph->version);
		return;
	}

	p->pkt_nxthdr += (iph->ihl << 2);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	len = sys_be16(iph->tot_len);
	if ( p->pkt_nxthdr > p->pkt_end ) {
		mesg(M_WARN, "ipv4: truncated IP packet");
		return;
	}

	if ( _ip_csum(iph) ) {
		mesg(M_WARN, "ipv4: bad checksum");
		return;
	}

	if ( iph->frag_off & ipfmask ) {
		struct ipfrag_dcb *dcb;
		dcb = (struct ipfrag_dcb *)_decode_layer(p, &p_fragment);
		if ( dcb ) {
			dcb->ip_iph = iph;
		}
		p->pkt_nxthdr = (uint8_t *)iph + len;
		return;
	}

	(*subproto[pmap[iph->protocol]])(p, iph, NULL);
	p->pkt_nxthdr = (uint8_t *)iph + len;
}
