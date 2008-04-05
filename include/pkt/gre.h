#ifndef __PKT_GRE_HEADER_INCLUDED__
#define __PKT_GRE_HEADER_INCLUDED__

/*
* 2 csum, res, ver
* proto
* csum
* reserved
*/

struct pkt_grehdr {
	uint16_t	c_res_ver;
	uint16_t	proto;
};

#endif /* __PKT_GRE_HEADER_INCLUDED__ */
