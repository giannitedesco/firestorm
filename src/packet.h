#ifndef _INTERNAL_PACKET_HEADER_INCLUDED_
#define _INTERNAL_PACKET_HEADER_INCLUDED_

struct _pkt {
	size_t		pkt_caplen;
	size_t		pkt_len;
	void		*pkt_base;
	void		*pkt_end;
	timestamp_t 	pkt_ts;
};

#endif /* _INTERNAL_PACKET_HEADER_INCLUDED_ */
