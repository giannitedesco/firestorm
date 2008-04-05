#ifndef __PKT_ICMP_HEADER_INCLUDED__
#define __PKT_ICMP_HEADER_INCLUDED__

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/

/* ICMP_DEST_UNREACH */
#define ICMP_NET_UNREACH	0
#define ICMP_HOST_UNREACH	1
#define ICMP_PROT_UNREACH	2
#define ICMP_PORT_UNREACH	3
#define ICMP_FRAG_NEEDED	4
#define ICMP_SR_FAILED		5
#define ICMP_NET_UNKNOWN	7
#define ICMP_HOST_UNKNOWN	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13
#define ICMP_PREC_VIOLATION	14
#define ICMP_PREC_CUTOFF	15
#define NR_ICMP_UNREACH		15

struct pkt_icmphdr {
	uint8_t	type;
	uint8_t	code;
	uint16_t	csum;
	union {
		uint32_t gateway;
		
		struct {
			uint16_t id;
			uint16_t seq;
		}echo;

		struct {
			uint16_t unused;
			uint16_t mtu;
		}frag;

		struct {
			uint8_t  num_addr;
			uint8_t  wpa;
			uint16_t lifetime;
		}advert;
	}un;
};

#endif /* __PKT_ICMP_HEADER_INCLUDED__ */
