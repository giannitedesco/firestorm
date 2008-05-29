#ifndef __PKT_SAP_HEADER_INCLUDED__
#define __PKT_SAP_HEADER_INCLUDED__

/* SAP packet */
struct pkt_sap {
	uint16_t op;		/* Operation */
	uint16_t service;	/* Service type*/
	uint8_t server_name[48]; /* Server name in quotes */
	uint32_t network;	/* Network address */
	uint8_t node[6];	/* Node address */
	uint16_t sock;		/* Socket address */
	uint16_t hops;	/* source net */
} _packed;

#endif /* __PKT_SAP_HEADER_INCLUDED__ */
