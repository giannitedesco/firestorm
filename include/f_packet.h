/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_PACKET_HEADER_INCLUDED_
#define _FIRESTORM_PACKET_HEADER_INCLUDED_

struct _frame {
	source_t	f_source;
	struct _pkt	*f_raw;
	struct list_head f_pkts;
	void		*f_priv;
};

struct _pkt {
	timestamp_t 	pkt_ts;

	size_t		pkt_caplen;
	size_t		pkt_len;
	const uint8_t	*pkt_base;
	const uint8_t	*pkt_end;

	const uint8_t	*pkt_nxthdr;

	struct _dcb	*pkt_dcb_top;
	struct _dcb	*pkt_dcb;
	struct _dcb	*pkt_dcb_end;

	/** Destructor function. Responsible for freeing up dcb and payload. */
	void (*pkt_dtor)(struct _pkt *pkt);

	/** Owning frame. May be NULL */
	struct _frame	*pkt_owner;

	/** Packet list entry in owning frame. */
	struct list_head pkt_list;
};

#endif /* _FIRESTORM_PACKET_HEADER_INCLUDED_ */
