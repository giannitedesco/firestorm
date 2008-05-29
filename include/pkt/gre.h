#ifndef _PKT_GRE_HEADER_INCLUDED_
#define _PKT_GRE_HEADER_INCLUDED_

/*
* 2 csum, res, ver
* proto
* csum
* reserved
*/

struct pkt_grehdr {
	uint16_t	c_res_ver;
	uint16_t	proto;
} _packed;

#endif /* _PKT_GRE_HEADER_INCLUDED_ */
