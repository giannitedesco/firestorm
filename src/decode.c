/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <stdio.h>

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>

static LIST_HEAD(netprotos);

netproto_t netproto_by_id(unsigned int id)
{
	struct _netproto *l;

	list_for_each_entry(l, &netprotos, np_list)
		if ( l->np_id == id )
			return l;

	return NULL;
}

const char *netproto_label(netproto_t l)
{
	assert(l->np_label != NULL);
	return l->np_label;
}

void netproto_register(struct _netproto *l)
{
	assert(l != NULL && l->np_label != NULL);
	mesg(M_INFO, "netproto: registered: %s (id 0x%x)",
		l->np_label, l->np_id);
	list_add_tail(&l->np_list, &netprotos);
}

void decode(struct _source *s, struct _pkt *p)
{
	p->pkt_nxthdr = p->pkt_base;
	s->s_linktype->np_decode(p);
}
