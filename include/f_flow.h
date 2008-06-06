/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_FLOW_HEADER_INCLUDED_
#define _FIRESTORM_FLOW_HEADER_INCLUDED_

struct _flow_tracker {
	struct _proto *ft_proto;
	pkt_t (*ft_track)(flow_state_t s, pkt_t pkt, dcb_t dcb);
	flow_state_t (*ft_ctor)(void);
	void (*ft_dtor)(flow_state_t s);
	struct _flow_tracker *ft_next;
	const char * const ft_label;
};

void flow_tracker_add(struct _flow_tracker *ft);
int flow_tracker_foreach(int(*cbfn)(struct _flow_tracker *f, void *priv),
				void *priv);

#endif /* _FIRESTORM_FLOW_HEADER_INCLUDED_ */
