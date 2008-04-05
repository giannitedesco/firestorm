#ifndef _PKT_VLAN_HEADER_INCLUDED_
#define _PKT_VLAN_HEADER_INCLUDED_

struct pkt_vlanhdr {
	uint16_t	vlan;
	uint16_t	proto;
};

#endif /* _PKT_VLAN_HEADER_INCLUDED_ */
