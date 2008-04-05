#ifndef _PKT_IPX_HEADER_INCLUDED_
#define _PKT_IPX_HEADER_INCLUDED_

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
	uint16_t checksum _packed;
	uint16_t pktsize _packed;
	uint8_t tctrl;	/* Transport Control (i.e. hop count) */
	uint8_t type; /* Packet Type (i.e. level 2 protocol) */
	struct ipx_addr dst _packed;
	struct ipx_addr src _packed;
};

#define ipxSize 30


#endif /* _PKT_IPX_HEADER_INCLUDED_ */
