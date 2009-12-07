/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_stream.h>

#define NAMESPACE_ALLOC_CHUNK	(1<<4)
#define NAMESPACE_ALLOC_MASK	(NAMESPACE_ALLOC_CHUNK-1)

static struct _stream_ns ns_arr[SNS_MAX] = {
	[SNS_TCP]	{.ns_label = "TCP"},
	[SNS_HTTP]	{.ns_label = "HTTP"},
	[SNS_RFC822]	{.ns_label = "RFC822"},
};

static struct _sproto *sprotos;
static unsigned int num_sproto;

static int ns_assure(struct _stream_ns *ns)
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

size_t stream_max_flow_size(proto_ns_t ns)
{
	unsigned int i;
	size_t max;
	for(i = 0, max = 0; i < ns_arr[ns].ns_num_reg; i++)
		if ( ns_arr[ns].ns_reg[i].nse_sproto->sp_flow_sz > max )
			max = ns_arr[ns].ns_reg[i].nse_sproto->sp_flow_sz;
	return max;
}

unsigned int stream_num_sproto(void)
{
	return num_sproto;
}

void sproto_add(struct _sproto *sp)
{
	assert(NULL != sp->sp_label);
	sp->sp_next = sprotos;
	sprotos = sp;
	sp->sp_idx = num_sproto++;
}

void sproto_register(struct _sproto *sp, proto_ns_t ns, proto_id_t id)
{
	unsigned int i;
	assert(ns < SNS_MAX);

	for(i = id; i < ns_arr[ns].ns_num_reg; i++) {
		if ( ns_arr[ns].ns_reg[i].nse_id == id ) {
			mesg(M_WARN, "stream : %s: %s / 0x%x registered by %s",
				sp->sp_label, ns_arr[ns].ns_label, id,
				ns_arr[ns].ns_reg[i].nse_sproto->sp_label);
			return;
		}
	}

	if ( !ns_assure(&ns_arr[ns]) ) {
		assert(ns_assure(&ns_arr[ns]));
		return;
	}

	ns_arr[ns].ns_reg[ns_arr[ns].ns_num_reg].nse_id = id;
	ns_arr[ns].ns_reg[ns_arr[ns].ns_num_reg].nse_sproto = sp;
	ns_arr[ns].ns_num_reg++;
}

const struct _sproto *sproto_find(proto_ns_t ns, proto_id_t id)
{
	struct _sns_entry *p = ns_arr[ns].ns_reg;
	unsigned int n;

	for(n = ns_arr[ns].ns_num_reg; n; ) {
		unsigned int i;

		i = (n / 2);
		if ( id < p[i].nse_id ) {
			n = i;
		}else if ( id > p[i].nse_id ) {
			p = p + (i + 1);
			n = n - (i + 1);
		}else{
			return p[i].nse_sproto;
		}
	}

	return NULL;
}

static int nsentry_cmp(const void *A, const void *B)
{
	const struct _sns_entry *a = A, *b = B;
	return a->nse_id - b->nse_id;
}

void stream_init(void)
{
	unsigned int i;

	for(i = 0; i < SNS_MAX; i++) {
		qsort(ns_arr[i].ns_reg,
			ns_arr[i].ns_num_reg,
			sizeof(*ns_arr[i].ns_reg),
			nsentry_cmp);
	}
}

ssize_t stream_push_line(struct ro_vec *vec, size_t numv, size_t bytes,
				size_t *bufsz)
{
	size_t v, i, b;

	for(b = v = 0; v < numv; b += vec[v].v_len, v++) {
		for(i = 0; i < vec[v].v_len; i++) {
			if ( vec[v].v_ptr[i] != '\n' )
				continue;
			*bufsz = b + i;
			if ( 0 != i ) {
				if ( vec[v].v_ptr[i - 1] == '\r' )
					*bufsz = b + i - 1;
			}
			if ( 0 != v ) {
				if ( '\r' == 
					vec[v - 1].v_ptr[vec[v - 1].v_len - 1] )
					*bufsz = b + i - 1;

			}
			return b + i + 1;
		}
	}

	return 0;
}

