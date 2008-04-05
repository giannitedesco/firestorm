#ifndef __PKT_IPX_HEADER_INCLUDED__
#define __PKT_IPX_HEADER_INCLUDED__

#define IPX_NO_CHECKSUM 0xffff
#define IPX_NODE_LEN 6

struct ipx_addr {
	uint32_t net;
	uint8_t node[IPX_NODE_LEN];
	uint16_t sock;
};

/* IPX transport header */
struct pkt_ipxhdr
{
	uint16_t checksum __attribute__((packed));
	uint16_t pktsize __attribute__((packed));
	uint8_t tctrl;	/* Transport Control (i.e. hop count) */
	uint8_t type; /* Packet Type (i.e. level 2 protocol) */
	struct ipx_addr dst __attribute__((packed));
	struct ipx_addr src __attribute__((packed));
};

#define ipxSize 30


#endif /* __PKT_IPX_HEADER_INCLUDED__ */
