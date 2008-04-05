#ifndef __PKT_SLL_HEADER_INCLUDED__
#define __PKT_SLL_HEADER_INCLUDED__

#define LINUX_SLL_HOST		0
#define LINUX_SLL_BROADCAST	1
#define LINUX_SLL_MULTICAST	2
#define LINUX_SLL_OTHERHOST	3
#define LINUX_SLL_OUTGOING	4

#define LINUX_SLL_P_802_3	0x0001 /* Novell 802.3 frames without 802.2 LLC header */
#define LINUX_SLL_P_802_2	0x0004 /* 802.2 frames (not D/I/X Ethernet) */

#define SLL_ADDRLEN 8
struct pkt_sllhdr {
	uint16_t	sll_pkttype;
	uint16_t	sll_hatype; /* link-layer address type */
	uint16_t	sll_halen; /* link-layer address length */
	uint8_t	sll_addr[SLL_ADDRLEN]; /* link-layer address */
	uint16_t	sll_protocol; /* protocol */
};

#endif /* __PKT_SLL_HEADER_INCLUDED__ */
