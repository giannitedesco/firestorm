/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_PACKET_HEADER_INCLUDED_
#define _FIRESTORM_PACKET_HEADER_INCLUDED_

#define PACKET_MAX_DECODE 3

struct _pkt {
	size_t		pkt_caplen;
	size_t		pkt_len;
	const uint8_t	*pkt_base;
	const uint8_t	*pkt_end;
	timestamp_t 	pkt_ts;

	const uint8_t	*pkt_nxthdr;
	source_t	pkt_source;
};

#endif /* _FIRESTORM_PACKET_HEADER_INCLUDED_ */
