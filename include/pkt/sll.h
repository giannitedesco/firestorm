#ifndef _PKT_SLL_HEADER_INCLUDED_
#define _PKT_SLL_HEADER_INCLUDED_

#define LINUX_SLL_HOST		0
#define LINUX_SLL_BROADCAST	1
#define LINUX_SLL_MULTICAST	2
#define LINUX_SLL_OTHERHOST	3
#define LINUX_SLL_OUTGOING	4

/* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_802_3	0x0001
/* 802.2 frames (not D/I/X Ethernet) */
#define LINUX_SLL_P_802_2	0x0004
/* PPP HDLC frames */
#define LINUX_SLL_P_PPPHDLC	0x0007

#define SLL_ADDRLEN 8
struct pkt_sllhdr {
	uint16_t	sll_pkttype;
	uint16_t	sll_hatype; /* link-layer address type */
	uint16_t	sll_halen; /* link-layer address length */
	uint8_t	sll_addr[SLL_ADDRLEN]; /* link-layer address */
	uint16_t	sll_protocol; /* protocol */
} _packed;

struct pkt_linuxhdr {
	unsigned short	sll_family;
	unsigned short	sll_protocol;
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];
} _packed;

#endif /* _PKT_SLL_HEADER_INCLUDED_ */
