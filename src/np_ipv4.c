/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>
#include <pkt/ip.h>

static const uint16_t ipfmask = const_be16(IP_MF|IP_OFFMASK);

static void ipv4_decode(struct _pkt *p);

static struct _proto p_raw = {
	.p_label = "rawip",
};

static struct _proto p_icmp = {
	.p_label = "icmp",
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

static struct _proto p_tcp = {
	.p_label = "tcp",
};

static struct _proto p_udp = {
	.p_label = "udp",
};

static struct _decoder decoder = {
	.d_label = "IPv4",
	.d_decode = ipv4_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&decoder);
	decoder_register(&decoder, NS_ETHER, const_be16(0x0800));
	decoder_register(&decoder, NS_UNIXPF, 2);
	proto_add(&decoder, &p_raw);
	proto_add(&decoder, &p_icmp);
	proto_add(&decoder, &p_igmp);
	proto_add(&decoder, &p_sctp);
	proto_add(&decoder, &p_dccp);
	proto_add(&decoder, &p_tcp);
	proto_add(&decoder, &p_udp);
}

static uint16_t ip_csum(const struct pkt_iphdr *iph)
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

static void esp_decode(struct _pkt *p)
{
	const struct pkt_esphdr *esp;

	esp = (struct pkt_esphdr *)p->pkt_nxthdr;
	p->pkt_nxthdr += sizeof(*esp);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;
	mesg(M_DEBUG, "ESP SPI=0x%.8x seq=0x%.8x",
		sys_be32(esp->spi), sys_be32(esp->seq));
	/* XXX: Need to know iph */
}

static void ah_decode(struct _pkt *p)
{
	const struct pkt_ahhdr *ah;

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

	mesg(M_DEBUG, "ipv4(ah) proto = 0x%.2x", ah->protocol);

	switch(ah->protocol) {
	case IP_PROTO_ICMP:
	case IP_PROTO_IGMP:
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		/* XXX: Need to know iph */
		//p->pkt_nxthdr = (uint8_t *)iph + len;
		break;
	case IP_PROTO_IPIP:
		ipv4_decode(p);
		break;
	case IP_PROTO_ESP:
		esp_decode(p);
		break;
	default:
		break;
	}
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

	if ( ip_csum(iph) ) {
		mesg(M_WARN, "bad checksum");
		return;
	}

	mesg(M_DEBUG, "IPv4 proto = 0x%.2x", iph->protocol);

	switch(iph->protocol) {
	case IP_PROTO_ICMP:
	case IP_PROTO_IGMP:
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		p->pkt_nxthdr = (uint8_t *)iph + len;
		break;
	case IP_PROTO_IPIP:
		ipv4_decode(p);
		break;
	case IP_PROTO_ESP:
		esp_decode(p);
		break;
	case IP_PROTO_AH:
		ah_decode(p);
		break;
	default:
		break;
	}
}
