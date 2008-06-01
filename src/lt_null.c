/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>

/* TODO: loopback: NS_ETHER / 0x9000 */
static void null_decode(struct _pkt *p);

static struct _decoder decoder = {
	.d_label = "Null Link",
	.d_decode = null_decode,
};

static struct _proto p_null = {
	.p_label = "null",
};

static void __attribute__((constructor)) _ctor(void)
{
	decoder_add(&decoder);
	decoder_register(&decoder, NS_DLT, 0);
	proto_add(&decoder, &p_null);
}

static void null_decode(struct _pkt *p)
{
	uint32_t *null;
	uint32_t proto;

	null = (uint32_t *)p->pkt_nxthdr;

	p->pkt_nxthdr += sizeof(*null);
	if ( p->pkt_nxthdr > p->pkt_end )
		return;

	proto = source_h32(p->pkt_source, *null);
	_decode_layer(p, &p_null);
	_decode_next(p, NS_UNIXPF, proto);
}
