/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <pkt/tcp.h>
#include <f_stream.h>

#define HTTP_STATE_REQ		0
#define HTTP_STATE_DATA 	1
#define HTTP_STATE_CHUNKED	2
struct http_fside {
	unsigned int state;
	size_t data_bytes;
};

struct http_flow {
	struct http_fside client, server;
};

static int check_req(struct ro_vec *vec, size_t vb, size_t b,
					size_t v, size_t i)
{
	uint8_t pb;

	if (b < vb)
		return 0;

	if ( 1 + vb == b )
		return 1;

	if ( b - vb > 2 )
		return 0;

	if ( i ) {
		pb = vec[v].v_ptr[i - 1];
	}else if ( v ) {
		pb = vec[v - 1].v_ptr[vec[v - 1].v_len - 1];
	}else
		return 9;

	return 1;
}

static ssize_t parse_ret;
static ssize_t parse_req(struct http_flow *f, struct http_fside *fs,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	size_t vb = bytes;
	size_t v, i, b;

	for(v = 0; v < numv; v++) {
		for(i = 0; i < vec[v].v_len; i++) {
			if ( vec[v].v_ptr[i] != '\n' )
				continue;
			if ( !check_req(vec, vb, b + i, v, i) ) {
				vb = b + i;
				continue;
			}
			parse_ret = b + i + 1;
			return b + i + 1;
		}
		b += vec[v].v_len;
	}

	parse_ret = 0;
	return 0;
}

static ssize_t push_req(struct _stream *s, struct http_flow *f,
			struct http_fside *fs,
			struct ro_vec *vec, size_t numv, size_t bytes)
{
	ssize_t ret;
	const uint8_t *buf;
	size_t len;

	/* Apparently a new feature in GCC... */
	ret = parse_req(f, fs, vec, numv, bytes);
	ret = parse_ret;
	if ( ret <= 0 )
		return ret;

	len = (size_t)ret;

	if ( vec[0].v_len < len ) {
		buf = malloc(len);
		if ( NULL == buf )
			return 0;
		ret = s->s_reasm(s, (uint8_t *)buf, len);
	}else{
		buf = vec[0].v_ptr;
	}

	mesg(M_DEBUG, "%u bytes request:\n%.*s", len, len, buf);

	if ( vec[0].v_len < len )
		free((void *)buf);

	return ret;
}

static ssize_t http_push(struct _stream *s, unsigned int chan,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	struct http_flow *f;
	struct http_fside *fs;
	ssize_t ret;

	f = s->s_flow;

	switch (chan) {
	case TCP_CHAN_TO_SERVER:
		fs = &f->client;
		break;
	case TCP_CHAN_TO_CLIENT:
		fs = &f->server;
		return bytes;
		break;
	default:
		return bytes;
	}

	switch(fs->state) {
	case HTTP_STATE_REQ:
		ret = push_req(s, f, fs, vec, numv, bytes);
		break;
	case HTTP_STATE_DATA:
		ret = bytes;
		break;
	case HTTP_STATE_CHUNKED:
		ret = bytes;
		break;
	default:
		assert(0);
	}

	return ret;
}

static int flow_init(void *fptr)
{
	struct http_flow *f = fptr;
	f->client.state = HTTP_STATE_REQ;
	f->server.state = HTTP_STATE_REQ;
	return 1;
}

static void flow_fini(void *fptr)
{
}


struct _sproto sp_http = {
	.sp_label = "http",
	.sp_push = http_push,
	.sp_flow_sz = sizeof(struct http_flow),
	.sp_flow_init = flow_init,
	.sp_flow_fini = flow_fini,
};

static void __attribute__((constructor)) http_ctor(void)
{
	sproto_add(&sp_http);
	sproto_register(&sp_http, SNS_TCP, sys_be16(80));
	sproto_register(&sp_http, SNS_TCP, sys_be16(3128));
	sproto_register(&sp_http, SNS_TCP, sys_be16(8080));
}
