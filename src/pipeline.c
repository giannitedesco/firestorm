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

struct per_proto {
	struct _flow_tracker *pp_ft;
	flow_state_t pp_flow;
};

struct _pipeline {
	struct list_head p_sources;
	unsigned int p_type;
	struct per_proto p_proto[0];
};

static int ft_init(struct _flow_tracker *ft, void *priv)
{
	struct _pipeline *p = priv;
	struct per_proto *pp;

	mesg(M_DEBUG, "flow: init %s", ft->ft_label);
	pp = &p->p_proto[ft->ft_proto->p_idx];
	if ( pp->pp_ft != NULL )
		return 0;

	pp->pp_ft = ft;
	if ( ft->ft_ctor ) {
		pp->pp_flow = ft->ft_ctor();
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

	INIT_LIST_HEAD(&p->p_sources);

	if ( !flow_tracker_foreach(ft_init, p) )
		goto out_free;

	goto out;

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

	list_for_each_entry_safe(s, tmp, &p->p_sources, s_list) {
		list_del(&s->s_list);
		_source_free(s);
	}

	for(i = 0; i < decode_num_protocols(); i++) {
		if ( p->p_proto[i].pp_ft &&
			p->p_proto[i].pp_ft->ft_dtor )
			p->p_proto[i].pp_ft->ft_dtor(p->p_proto[i].pp_flow);
	}

	free(p);
}

int pipeline_add_source(pipeline_t p, source_t s)
{
	unsigned int type;

	assert(p != NULL);
	assert(s != NULL);
	assert(s->s_capdev != NULL);

	type = (s->s_capdev->c_flags & CAPDEV_ASYNC) == 0;
	if ( list_empty(&p->p_sources) ) {
		p->p_type = type;
	}else if ( type != p->p_type ) {
		mesg(M_ERR, "%s: adding %s[%s]: cannot mix sync and async "
			"captures.", __FUNCTION__,
			s->s_capdev->c_name, s->s_name);
		return 0;
	}

	list_add_tail(&s->s_list, &p->p_sources);
	return 1;
}

#if 1
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do{}while(0);
#define dhex_dump(x...) do{}while(0);
#endif

static void analyze(struct _pipeline *p, struct _pkt *pkt)
{
	struct _dcb *cur;
	struct per_proto *pp;

	for(cur = pkt->pkt_dcb; cur < pkt->pkt_dcb_top; cur = cur->dcb_next) {
		dmesg(M_DEBUG, "DECODED: %s", cur->dcb_proto->p_label);
		pp = &p->p_proto[cur->dcb_proto->p_idx];
		if ( pp->pp_ft && pp->pp_ft->ft_track )
			pp->pp_ft->ft_track(pp->pp_flow, pkt, cur);
	}
}

int pipeline_go(pipeline_t p)
{
	static unsigned int n;
	struct _source *s, *tmp;
	pkt_t pkt;

	list_for_each_entry_safe(s, tmp, &p->p_sources, s_list) {
		mesg(M_INFO, "pipeline: starting: %s[%s]",
			s->s_capdev->c_name, s->s_name);
		for(;;){
			pkt = s->s_capdev->c_dequeue(s);
			if ( pkt == NULL )
				break;

			n++;
			dmesg(M_DEBUG, "packet %u, len = %u/%u",
				n, pkt->pkt_caplen, pkt->pkt_len);
			decode(s, pkt);
			analyze(p, pkt);
			if ( pkt->pkt_nxthdr < pkt->pkt_end ) {
				dhex_dump(pkt->pkt_nxthdr,
					pkt->pkt_end - pkt->pkt_nxthdr, 16);
			}else{
				dmesg(M_DEBUG, ".\n");
			}
		}
		mesg(M_INFO, "pipeline: finishing: %s[%s]",
			s->s_capdev->c_name, s->s_name);
		list_del(&s->s_list);
		_source_free(s);
	}

	mesg(M_DEBUG, "%u packets in total", n);
	return 1;
}
