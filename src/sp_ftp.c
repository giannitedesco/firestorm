/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <pkt/tcp.h>
#include <f_stream.h>

#include <limits.h>
#include <ctype.h>

#define FTP_STATE_INIT 		0
#define FTP_STATE_CMD 		1
#define FTP_STATE_RESP 		2
#define FTP_STATE_MAX 		3
struct ftp_flow {
	uint8_t state;
};

static int ftp_line(struct _stream *s, struct ftp_flow *f,
			unsigned int chan, const uint8_t *ptr, size_t len)
{
	struct ro_vec vec;

	assert(f->state < FTP_STATE_MAX);

	vec.v_ptr = ptr;
	vec.v_len = len;

	switch(chan) {
	case TCP_CHAN_TO_CLIENT:
		break;
	case TCP_CHAN_TO_SERVER:
		break;
	default:
		break;
	}

	return 1;
}

static ssize_t ftp_push(struct _stream *s, unsigned int chan,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	struct ftp_flow *f;
	const uint8_t *buf;
	ssize_t ret;
	size_t sz;
	int do_free;

	f = s->s_flow;

	ret = stream_push_line(vec, numv, bytes, &sz);
	if ( ret <= 0 )
		return ret;
	
	if ( sz > vec[0].v_len ) {
		buf = malloc(sz);
		s->s_reasm(s, (uint8_t *)buf, sz);
		do_free = 1;
	}else{
		buf = vec[0].v_ptr;
		do_free = 0;
	}

	if ( !ftp_line(s, f, chan, buf, sz) )
		ret = 0;

	if ( do_free )
		free((void *)buf);

	return ret;
}

static int flow_init(struct _stream *s)
{
	struct ftp_flow *f = s->s_flow;
	f->state = FTP_STATE_INIT;
	return 1;
}

static void flow_fini(struct _stream *s)
{
}


struct _sproto sp_ftp = {
	.sp_label = "ftp",
	.sp_push = ftp_push,
	.sp_flow_sz = sizeof(struct ftp_flow),
	.sp_flow_init = flow_init,
	.sp_flow_fini = flow_fini,
};

static void __attribute__((constructor)) ftp_ctor(void)
{
	sproto_add(&sp_ftp);
	sproto_register(&sp_ftp, SNS_TCP, sys_be16(21));
}
