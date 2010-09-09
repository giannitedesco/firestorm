/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_PACKET_HEADER_INCLUDED_
#define _FIRESTORM_PACKET_HEADER_INCLUDED_

struct _pkt {
	source_t	pkt_source;
	timestamp_t 	pkt_ts;

	size_t		pkt_caplen;
	size_t		pkt_len;
	const uint8_t	*pkt_base;
	const uint8_t	*pkt_end;

	const uint8_t	*pkt_nxthdr;

	struct _dcb	*pkt_dcb_top;
	struct _dcb	*pkt_dcb;
	struct _dcb	*pkt_dcb_end;
};

#endif /* _FIRESTORM_PACKET_HEADER_INCLUDED_ */
