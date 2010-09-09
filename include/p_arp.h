/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _P_ARP_HEADER_INCLUDED_
#define _P_ARP_HEADER_INCLUDED_

struct arp_dcb {
	struct _dcb arp_dcb;
	const struct pkt_arphdr *arp_hdr;
	const uint8_t *arp_sha;
	const uint8_t *arp_spa;
	const uint8_t *arp_tha;
	const uint8_t *arp_tpa;
};

#endif /* _P_ARP_HEADER_INCLUDED_ */
