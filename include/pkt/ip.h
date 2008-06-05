#ifndef __PKT_IP_HEADER_INCLUDED__
#define __PKT_IP_HEADER_INCLUDED__

#define FLAG_IP_REASM	0x01 /* This packet is a reassemblygram */
#define FLAG_IP_CSUM	0x02 /* Checksum is OK */
#define FLAG_IP_DTRUNC	0x04 /* Datagram is truncated */

#define IP_CE 		0x8000	/* Congestion */
#define IP_DF 		0x4000	/* dont fragment flag */
#define IP_MF 		0x2000	/* more fragments flag */
#define IP_OFFMASK 	0x1fff	/* mask for fragmenting bits */

#define IPOPT_EOL	0x00
#define IPOPT_NOP	0x01
#define IPOPT_RR	0x07
#define IPOPT_RTRALT	0x14
#define IPOPT_TS	0x44
#define IPOPT_SECURITY	0x82
#define IPOPT_LSRR	0x83
#define IPOPT_LSRR_E	0x84
#define IPOPT_SATID	0x88
#define IPOPT_SSRR	0x89

#define IP_PROTO_ICMP	0x01
#define IP_PROTO_IGMP	0x02
#define IP_PROTO_IPIP	0x04
#define IP_PROTO_TCP	0x06
#define IP_PROTO_UDP	0x11
#define IP_PROTO_DCCP	0x21
#define IP_PROTO_ESP	0x32
#define IP_PROTO_AH	0x33
#define IP_PROTO_SCTP	0x84

struct pkt_iphdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t	ihl:4;
	uint8_t	version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t	version:4;
	uint8_t	ihl:4;
#else
#error "Couldn't determine endianness"
#endif
	uint8_t	tos;
	uint16_t	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t	ttl;
	uint8_t	protocol;
	uint16_t	csum;
	uint32_t	saddr;
	uint32_t	daddr;
}_packed;

struct pkt_ahhdr {
	uint8_t protocol;
	uint8_t ahl;
	uint32_t spi;
	uint32_t seq;
} _packed;

struct pkt_esphdr {
	uint32_t spi;
	uint32_t seq;
} _packed;

#endif /* __PKT_IP_HEADER_INCLUDED__ */
