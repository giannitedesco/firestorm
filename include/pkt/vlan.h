#ifndef __PKT_VLAN_HEADER_INCLUDED__
#define __PKT_VLAN_HEADER_INCLUDED__

struct pkt_vlanhdr {
	uint16_t	vlan;
	uint16_t	proto;
};

#endif /* __PKT_VLAN_HEADER_INCLUDED__ */
