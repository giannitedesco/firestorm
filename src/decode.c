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

#define NAMESPACE_ALLOC_CHUNK	(1<<4)
#define NAMESPACE_ALLOC_MASK	(NAMESPACE_ALLOC_CHUNK-1)

static struct _namespace ns_arr[NS_MAX] = {
	[NS_DLT]	{.ns_label = "DLT"},
	[NS_UNIXPF]	{.ns_label = "UNIX"},
	[NS_ETHER]	{.ns_label = "ETHER"},
	[NS_INET]	{.ns_label = "INET"},
	[NS_INET6]	{.ns_label = "INET6"},
	[NS_IPX]	{.ns_label = "IPX"},
	[NS_APPLE]	{.ns_label = "APPLE"},
	[NS_CISCO]	{.ns_label = "CISCO"},
};

static unsigned int num_decoders;
static struct _decoder *decoders;

static unsigned int num_protos;
/* special protos have no decoder which owns them */
static struct _proto *special_protos;

static size_t max_dcb;

_constfn static struct _decoder *
ns_entry_search(const struct _ns_entry *p, unsigned int n, proto_id_t id)
{
	while( n ) {
		unsigned int i;

		i = (n / 2);
		if ( id < p[i].nse_id ) {
			n = i;
		}else if ( id > p[i].nse_id ) {
			p = p + (i + 1);
			n = n - (i + 1);
		}else{
			return p[i].nse_decoder;
		}
	}

	return NULL;
}

static struct _dcb *dcb_alloc(pkt_t p, size_t sz)
{
	struct _dcb *ret = p->pkt_dcb_top;
	uint8_t *ptr = (uint8_t *)ret;

	p->pkt_dcb_top = (struct _dcb *)(ptr + sz);

	if ( p->pkt_dcb_top > p->pkt_dcb_end )
		return NULL;

	ret->dcb_next = p->pkt_dcb_top;

	return (struct _dcb *)ret;
}

size_t decode_dcb_len(struct _dcb *dcb)
{
	uint8_t *ptr, *nxt;

	ptr = (uint8_t *)dcb;
	nxt = (uint8_t *)dcb->dcb_next;

	assert(nxt > ptr);

	return nxt - ptr;
}

struct _dcb *decode_layer(pkt_t pkt, struct _proto *p)
{
	struct _dcb *ret;
	ret = dcb_alloc(pkt, p->p_dcb_sz);
	if ( ret )
		ret->dcb_proto = p;
	return ret;
}

struct _dcb *decode_layer2(pkt_t pkt, struct _proto *p, size_t sz)
{
	struct _dcb *ret;
	assert(sz <= p->p_dcb_sz);
	ret = dcb_alloc(pkt, sz);
	if ( ret )
		ret->dcb_proto = p;
	return ret;
}

void decode_next(pkt_t pkt, proto_ns_t ns, proto_id_t id)
{
	const struct _decoder *d;
	d = ns_entry_search(ns_arr[ns].ns_reg, ns_arr[ns].ns_num_reg, id);
	if ( d != NULL )
		d->d_decode(pkt);
}

unsigned int decode_num_protocols(void)
{
	return num_protos;
}

unsigned int decode_num_decoders(void)
{
	return num_decoders;
}

size_t decode_max_dcb_size(void)
{
	return max_dcb;
}

void proto_add(struct _decoder *d, struct _proto *p)
{
	assert(p != NULL && p->p_label != NULL);
	assert(d == NULL || d->d_label != NULL);
	assert(p->p_next == NULL && p->p_owner == NULL);

	if ( p->p_dcb_sz == 0 )
		p->p_dcb_sz = sizeof(struct _dcb);

	p->p_owner = d;
	p->p_idx = num_protos++;

	if ( d ) {
		p->p_next = d->d_protos;
		d->d_protos = p;
	}else{
		p->p_next = special_protos;
		special_protos = p;
	}
}

decoder_t decoder_get(proto_ns_t ns, proto_id_t id)
{
	assert(ns < NS_MAX);
	return ns_entry_search(ns_arr[ns].ns_reg,
				ns_arr[ns].ns_num_reg, id);
}

static int nsentry_cmp(const void *A, const void *B)
{
	const struct _ns_entry *a = A, *b = B;
	return a->nse_id - b->nse_id;
}

void decode_init(void)
{
	static char * const fn = "decode.dot";
	struct _decoder *d;
	struct _proto *p;
	unsigned int i;
	FILE *f;
	static int called;

	assert(called == 0);
	called = 1;

	f = fopen(fn, "w");
	assert(f != NULL);

	fprintf(f, "strict digraph \"Internal Decode Graph\" {\n");
	fprintf(f, "\tgraph[rankdir=LR];\n");
	fprintf(f, "\tnode[shape=rectangle, style=filled, "
			"fillcolor=transparent];\n");

	for(i = 0; i < NS_MAX; i++) {
		unsigned int j;

		/* for binary search */
		qsort(ns_arr[i].ns_reg,
			ns_arr[i].ns_num_reg,
			sizeof(*ns_arr[i].ns_reg),
			nsentry_cmp);

		if ( ns_arr[i].ns_num_reg )
			fprintf(f, "\t\"ns_%s\" [label=\"%s\" "
				"fillcolor=\"#b0b0ff\"];\n",
				ns_arr[i].ns_label,
				ns_arr[i].ns_label);
		for(j = 0; j < ns_arr[i].ns_num_reg; j++)
			fprintf(f, "\t\"ns_%s\" -> \"d_%s\" "
				"[label=\"0x%x\" color=red];\n",
				ns_arr[i].ns_label,
				ns_arr[i].ns_reg[j].nse_decoder->d_label,
				ns_arr[i].ns_reg[j].nse_id);
	}

	for(d = decoders; d; d = d->d_next) {
		fprintf(f, "\t\"d_%s\" [label=\"%s\" "
			"fillcolor=\"#b0ffb0\"];\n",
			d->d_label, d->d_label);

		for(p = d->d_protos; p; p = p->p_next) {
			if ( p->p_dcb_sz > max_dcb )
				max_dcb = p->p_dcb_sz;

			fprintf(f, "\t\"d_%s\" -> \"p_%s\";\n",
				d->d_label, p->p_label);
			fprintf(f, "\t\"p_%s\" [label=\"%s\" "
				"fillcolor=\"#ffb0b0\"];\n",
				p->p_label, p->p_label);
		}
	}

	for(p = special_protos; p; p = p->p_next) {
		if ( p->p_dcb_sz > max_dcb )
			max_dcb = p->p_dcb_sz;
		fprintf(f, "\t\"p_%s\" [label=\"<< %s >>\" "
			"fillcolor=\"#ffb0b0\"\n];",
			p->p_label, p->p_label);
	}

	fprintf(f, "}\n");
	fclose(f);

	mesg(M_INFO, "decode: %s: dumped protocol graph", fn);
	mesg(M_INFO, "decode: %u decoders, %u protocols, max dcb = %u bytes",
		num_decoders, num_protos, max_dcb);
	mesg(M_INFO, "packet = %u + %u bytes", sizeof(struct _pkt),
		max_dcb * DECODE_DEFAULT_MIN_LAYERS);
}

const char *decoder_label(decoder_t d)
{
	assert(d->d_label != NULL);
	return d->d_label;
}

void decoder_add(struct _decoder *d)
{
	assert(d != NULL && d->d_label != NULL);
	d->d_next = decoders;
	decoders = d;
	d->d_idx = num_decoders++;
}

static int ns_assure(struct _namespace *ns)
{
	static void *new;

	if ( ns->ns_num_reg & NAMESPACE_ALLOC_MASK )
		return 1;

	new = realloc(ns->ns_reg,
			sizeof(*ns->ns_reg) *
			(ns->ns_num_reg + NAMESPACE_ALLOC_CHUNK));
	if ( new == NULL )
		return 0;
	
	ns->ns_reg = new;
	return 1;
}

void decoder_register(struct _decoder *d, proto_ns_t ns, proto_id_t id)
{
	unsigned int i;
	assert(ns < NS_MAX);

	for(i = id; i < ns_arr[ns].ns_num_reg; i++) {
		if ( ns_arr[ns].ns_reg[i].nse_id == id ) {
			mesg(M_WARN, "decode: %s: %s / 0x%x registered by %s",
				d->d_label, ns_arr[ns].ns_label, id,
				ns_arr[ns].ns_reg[i].nse_decoder->d_label);
			return;
		}
	}

	if ( !ns_assure(&ns_arr[ns]) ) {
		assert(ns_assure(&ns_arr[ns]));
		return;
	}

	ns_arr[ns].ns_reg[ns_arr[ns].ns_num_reg].nse_id = id;
	ns_arr[ns].ns_reg[ns_arr[ns].ns_num_reg].nse_decoder = d;
	ns_arr[ns].ns_num_reg++;

	return;
}

int decode_foreach_protocol(int(*cbfn)(struct _proto *p, void *priv),
				void *priv)
{
	struct _decoder *d;
	struct _proto *p;
	int ret = 1;

	for(d = decoders; d; d = d->d_next) {
		for(p = d->d_protos; p; p = p->p_next) {
			ret = (*cbfn)(p, priv);
			if ( ret == 0 )
				return 0;
		}
	}

	for(p = special_protos; p; p = p->p_next) {
		ret = (*cbfn)(p, priv);
		if ( ret == 0 )
			return 0;
	}

	return ret;
}

int decode_foreach_decoder(int(*cbfn)(decoder_t, void *priv), void *priv)
{
	struct _decoder *d;
	int ret = 1;

	for(d = decoders; d; d = d->d_next) {
		ret = (*cbfn)(d, priv);
		if ( ret == 0 )
			return 0;
	}

	return ret;;
}

int decode_pkt_realloc(struct _pkt *p, unsigned int min_layers)
{
	uint8_t *new;

	new = realloc(p->pkt_dcb, min_layers * max_dcb);
	if ( min_layers && new == NULL )
		return 0;
	
	p->pkt_dcb = (void *)new;
	p->pkt_dcb_end = (void *)(new + (min_layers * max_dcb));

	return 1;
}

void decode(struct _pkt *p, struct _decoder *d)
{
	p->pkt_nxthdr = p->pkt_base;
	p->pkt_dcb_top = p->pkt_dcb;
	d->d_decode(p);
}
