/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>

static void null_decode(struct _pkt *p)
{
	uint32_t *null;
	uint32_t proto;

	null = (uint32_t *)p->pkt_nxthdr;

	p->pkt_nxthdr += 4;
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	/* FIXME: subtle endian bug */
	proto = sys_be32(*null);
	mesg(M_DEBUG, "Null packet");
}

static struct _linktype lt = {
	.lt_id = 0,
	.lt_label = "Null Link",
	.lt_decode = null_decode,
};

static void __attribute__((constructor)) _ctor(void)
{
	linktype_register(&lt);
}
