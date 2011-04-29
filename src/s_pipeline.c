/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>
#include <nbio.h>

#if 0
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do{}while(0);
#define dhex_dump(x...) do{}while(0);
#endif

struct _pipeline {
	struct iothread p_io;
	struct list_head p_sources;
	unsigned int p_async;
	uint64_t p_num_pkt;
};

static void analyze_packet(struct _pkt *pkt)
{
	struct _dcb *cur;

	for(cur = pkt->pkt_dcb;
		cur < pkt->pkt_dcb_top; cur = cur->dcb_next) {
		dmesg(M_DEBUG, " o %s layer", cur->dcb_proto->p_label);
	}
}

static void flowtrack_packet(struct _pkt *pkt)
{
	struct _dcb *cur;

	for(cur = pkt->pkt_dcb; cur < pkt->pkt_dcb_top; cur = cur->dcb_next) {
		if ( cur->dcb_proto->p_flowtrack ) {
			dmesg(M_DEBUG, "FLOW TRACK: %s",
				cur->dcb_proto->p_label);
			cur->dcb_proto->p_flowtrack(pkt, cur);
		}
	}
}

static void do_pkt_inject(pkt_t pkt)
{
	dmesg(M_DEBUG, "pkt: len=%u/%u", pkt->pkt_caplen, pkt->pkt_len);
	analyze_packet(pkt);
	flowtrack_packet(pkt);
	if ( pkt->pkt_nxthdr < pkt->pkt_end ) {
		dhex_dump(pkt->pkt_nxthdr,
			pkt->pkt_end - pkt->pkt_nxthdr, 16);
	}else{
		dmesg(M_DEBUG, ".\n");
	}
}

void pkt_inject(pkt_t pkt)
{
	do_pkt_inject(pkt);
}

static int pd_init(struct _decoder *d, void *priv)
{
	//struct _pipeline *p = priv;

	if ( d->d_flow_ctor ) {
		if ( !d->d_flow_ctor() )
			return 0;
	}

	return 1;
}

pipeline_t pipeline_new(void)
{
	struct _pipeline *p = NULL;
	unsigned int num;

	p = calloc(1, sizeof(*p));
	if ( NULL == p )
		return NULL;
	num = decode_num_protocols();

	INIT_LIST_HEAD(&p->p_sources);

	if ( !decode_foreach_decoder(pd_init, p) )
		goto out_free;

	goto out;

out_free:
	free(p);
	p = NULL;
out:
	return p;
}

static int pd_fini(struct _decoder *d, void *priv)
{
	//struct _pipeline *p = priv;

	if ( d->d_flow_dtor )
		d->d_flow_dtor();

	return 1;
}

void pipeline_free(pipeline_t p)
{
	struct _source *s, *tmp;

	if ( p == NULL )
		return;

	decode_foreach_decoder(pd_fini, p);

	list_for_each_entry_safe(s, tmp, &p->p_sources, s_list)
		source_free(s);

	free(p);
}

int pipeline_add_source(pipeline_t p, source_t s)
{
	unsigned int type;

	assert(p != NULL);
	assert(s != NULL);
	assert(s->s_capdev != NULL);

	type = !!(s->s_capdev->c_flags & CAPDEV_ASYNC);
	if ( list_empty(&p->p_sources) ) {
		p->p_async = type;
	}else if ( type != p->p_async ) {
		mesg(M_ERR, "%s: adding %s[%s]: cannot mix sync and async "
			"captures.", __FUNCTION__,
			s->s_capdev->c_name, s->s_name);
		return 0;
	}

	list_add_tail(&s->s_list, &p->p_sources);
	return 1;
}

static unsigned int do_dequeue(struct _pipeline *p, struct _source *s,
				struct iothread *io)
{
	pkt_t pkt;

	pkt = s->s_capdev->c_dequeue(s, io);
	if ( NULL == pkt )
		return 0;

	p->p_num_pkt++;

	dmesg(M_DEBUG, "Frame %llu:",
		p->p_num_pkt);

	decode(pkt, s->s_decoder);
	do_pkt_inject(pkt);

	return 1;
}

static int go_sync(struct _pipeline *p)
{
	struct _source *s, *tmp;

	list_for_each_entry_safe(s, tmp, &p->p_sources, s_list) {
		mesg(M_INFO, "pipeline: starting: %s[%s]",
			s->s_capdev->c_name, s->s_name);

		while(do_dequeue(p, s, NULL))
			/* do nothing */;

		mesg(M_INFO, "pipeline: finishing: %s[%s]",
			s->s_capdev->c_name, s->s_name);
		source_free(s);
	}

	return 1;
}

static void a_rw(struct iothread *io, struct nbio *n)
{
	struct _pipeline *p = (struct _pipeline *)io;
	while ( do_dequeue(p, (struct _source *)n, &p->p_io) )
		/* nothing */;
}

static void a_dtor(struct iothread *io, struct nbio *n)
{
	source_free((struct _source *)n);
}

static const struct nbio_ops async_ops = {
	.read = a_rw,
	.write = a_rw,
	.dtor = a_dtor,
};

static int go_async(struct _pipeline *p)
{
	struct _source *s;

	list_for_each_entry(s, &p->p_sources, s_list) {
		mesg(M_INFO, "pipeline: starting async: %s[%s]",
			s->s_capdev->c_name, s->s_name);
		s->s_io.ops = &async_ops;
		nbio_add(&p->p_io, &s->s_io, NBIO_READ);
	}
	
	do {
		nbio_pump(&p->p_io, -1);
	}while( !list_empty(&p->p_io.active) ||
		!list_empty(&p->p_io.inactive) );

	return 1;
}

int pipeline_go(pipeline_t p)
{
	int ret;

	if ( p->p_async ) {
		if ( !nbio_init(&p->p_io, NULL) )
			return 0;
		ret = go_async(p);
		nbio_fini(&p->p_io);
	}else{
		ret = go_sync(p);
	}

	mesg(M_INFO, "pipeline: %"PRIu64" packets in total", p->p_num_pkt);
	return ret;
}
