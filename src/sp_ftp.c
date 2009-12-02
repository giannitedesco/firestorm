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

struct ftp_flow {
	uint8_t state;
};

static ssize_t ftp_push(struct _stream *s, unsigned int chan,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	struct ftp_flow *f;
	ssize_t ret;
	size_t sz;

	f = s->s_flow;

	ret = stream_push_line(vec, numv, bytes, &sz);
	if ( ret <= 0 )
		return ret;
	
	if ( sz > vec[0].v_len ) {
	}else{
	}

	return ret;
}

static int flow_init(void *fptr)
{
	struct ftp_flow *f = fptr;
	f->state = 0;
	return 1;
}

static void flow_fini(void *fptr)
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
