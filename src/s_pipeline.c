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

struct per_decoder {
	flow_state_t pd_flow;
};

struct _pipeline {
	struct iothread p_io;
	struct list_head p_sources;
	unsigned int p_async;
	uint64_t p_num_pkt;
	struct per_decoder p_pd[0];
};

static void analyze_packet(struct _pipeline *p, struct _pkt *pkt)
{
	struct _dcb *cur;

	dmesg(M_DEBUG, "analyze packet:");
	for(cur = pkt->pkt_dcb;
		cur < pkt->pkt_dcb_top; cur = cur->dcb_next) {
		dmesg(M_DEBUG, " o %s layer", cur->dcb_proto->p_label);
	}
}

static int pd_init(struct _decoder *d, void *priv)
{
	struct _pipeline *p = priv;
	struct per_decoder *pd;

	pd = &p->p_pd[d->d_idx];

	if ( d->d_flow_ctor ) {
		pd->pd_flow = d->d_flow_ctor();
		if ( pd->pd_flow == NULL )
			return 0;
	}

	return 1;
}

pipeline_t pipeline_new(void)
{
	struct _pipeline *p = NULL;
	unsigned int num;

	num = decode_num_protocols();

	p = calloc(1, sizeof(*p) + sizeof(*p->p_pd) * num);
	if ( p == NULL )
		goto out;

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
	struct _pipeline *p = priv;
	struct per_decoder *pd;

	pd = &p->p_pd[d->d_idx];

	if ( d->d_flow_dtor )
		d->d_flow_dtor(pd->pd_flow);

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

static void flowtrack_packet(struct _pipeline *p, struct _pkt *pkt)
{
	struct _dcb *cur;
	struct per_decoder *pd;

	for(cur = pkt->pkt_dcb; cur < pkt->pkt_dcb_top; cur = cur->dcb_next) {
		if ( cur->dcb_proto->p_flowtrack ) {
			pd = &p->p_pd[cur->dcb_proto->p_owner->d_idx];
			dmesg(M_DEBUG, "FLOW TRACK: %s",
				cur->dcb_proto->p_label);
			cur->dcb_proto->p_flowtrack(pd->pd_flow, pkt, cur);
		}
	}
}

static unsigned int do_dequeue(struct _pipeline *p, struct _source *s,
				struct iothread *io)
{
	frame_t f;
	pkt_t pkt, tmp;

	f = s->s_capdev->c_dequeue(s, io);
	if ( f == NULL )
		return 0;

	f->f_priv = p;
	p->p_num_pkt++;

	dmesg(M_DEBUG, "Frame %llu, len = %u/%u",
		p->p_num_pkt, f->f_raw->pkt_caplen, f->f_raw->pkt_len);

	decode(f->f_raw, s->s_decoder);

	flowtrack_packet(p, f->f_raw);
	analyze_packet(p, f->f_raw);

	list_for_each_entry_safe(pkt, tmp, &f->f_pkts, pkt_list) {
		flowtrack_packet(p, pkt);
		analyze_packet(p, pkt);
		pkt_free(pkt);
	}

	if ( f->f_raw->pkt_nxthdr < f->f_raw->pkt_end ) {
		dhex_dump(f->f_raw->pkt_nxthdr,
			f->f_raw->pkt_end - f->f_raw->pkt_nxthdr, 16);
	}else{
		dmesg(M_DEBUG, ".\n");
	}

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

	mesg(M_INFO, "pipeline: %llu packets in total", p->p_num_pkt);
	return ret;
}
