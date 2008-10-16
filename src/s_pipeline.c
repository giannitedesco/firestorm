/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_flow.h>
#include <nbio.h>

#if 1
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do{}while(0);
#define dhex_dump(x...) do{}while(0);
#endif

struct per_proto {
	struct _flow_tracker *pp_ft;
	flow_state_t pp_flow;
};

struct _pipeline {
	struct list_head p_sources;
	unsigned int p_async;
	struct iothread p_io;
	memchunk_t p_mem;
	uint64_t p_num_pkt;
	struct per_proto p_proto[0];
};

static void analyze_packet(struct _pipeline *p, struct _pkt *pkt)
{
	struct _dcb *cur;
	struct per_proto *pp;

	dmesg(M_DEBUG, "analyze packet:");
	for(cur = pkt->pkt_dcb;
		cur < pkt->pkt_dcb_top; cur = cur->dcb_next) {
		pp = &p->p_proto[cur->dcb_proto->p_idx];
		dmesg(M_DEBUG, " o %s layer", cur->dcb_proto->p_label);
	}
}

static int ft_init(struct _flow_tracker *ft, void *priv)
{
	struct _pipeline *p = priv;
	struct per_proto *pp;

	pp = &p->p_proto[ft->ft_proto->p_idx];
	if ( pp->pp_ft != NULL )
		return 0;

	pp->pp_ft = ft;
	if ( ft->ft_ctor ) {
		pp->pp_flow = ft->ft_ctor(p->p_mem);
		if ( pp->pp_flow == NULL )
			return 0;
	}

	return 1;
}

pipeline_t pipeline_new(void)
{
	struct _pipeline *p = NULL;
	unsigned int num;

	num = decode_num_protocols();

	p = calloc(1, sizeof(*p) + sizeof(*p->p_proto) * num);
	if ( p == NULL )
		goto out;

	p->p_mem = memchunk_init(2048);
	if ( p->p_mem == NULL )
		goto out_free;

	INIT_LIST_HEAD(&p->p_sources);

	if ( !flow_tracker_foreach(ft_init, p) )
		goto out_free_chunk;

	goto out;

out_free_chunk:
	memchunk_fini(p->p_mem);
out_free:
	free(p);
	p = NULL;
out:
	return p;
}

void pipeline_free(pipeline_t p)
{
	struct _source *s, *tmp;
	unsigned int i;

	if ( p == NULL )
		return;

	list_for_each_entry_safe(s, tmp, &p->p_sources, s_list) {
		source_free(s);
	}

	for(i = 0; i < decode_num_protocols(); i++) {
		if ( p->p_proto[i].pp_ft &&
			p->p_proto[i].pp_ft->ft_dtor )
			p->p_proto[i].pp_ft->ft_dtor(p->p_mem,
						p->p_proto[i].pp_flow);
	}

	memchunk_fini(p->p_mem);

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
	struct per_proto *pp;

	for(cur = pkt->pkt_dcb; cur < pkt->pkt_dcb_top; cur = cur->dcb_next) {
		pp = &p->p_proto[cur->dcb_proto->p_idx];
		if ( pp->pp_ft && pp->pp_ft->ft_track ) {
			dmesg(M_DEBUG, "FLOW TRACK: %s",
				cur->dcb_proto->p_label);
			pp->pp_ft->ft_track(pp->pp_flow, pkt, cur);
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
	/* It suffices to get in to the active queue which is
	 * manually processed in go_async()
	 */
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
	struct nbio *n, *tmp;

	list_for_each_entry(s, &p->p_sources, s_list) {
		mesg(M_INFO, "pipeline: starting async: %s[%s]",
			s->s_capdev->c_name, s->s_name);
		s->s_io.ops = &async_ops;
		nbio_add(&p->p_io, &s->s_io, NBIO_READ);
	}
	
	do {
		unsigned int tmo;

		list_for_each_entry_safe(n, tmp, &p->p_io.active, list) {
			while ( do_dequeue(p, (struct _source *)n, &p->p_io) )
				/* nothing */;
		}

		/* No timers (yet) */
		tmo = -1;

		nbio_pump(&p->p_io, tmo);
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
