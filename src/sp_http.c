/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <pkt/tcp.h>
#include <f_stream.h>

struct http_flow {
};

static ssize_t http_push(struct _stream *s, unsigned int chan,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	return bytes;
}

struct _sproto sp_http = {
	.sp_label = "http",
	.sp_push = http_push,
	.sp_flow_sz = sizeof(struct http_flow),
};

static void __attribute__((constructor)) http_ctor(void)
{
	sproto_add(&sp_http);
	sproto_register(&sp_http, SNS_TCP, 80);
	sproto_register(&sp_http, SNS_TCP, 3128);
	sproto_register(&sp_http, SNS_TCP, 8080);
}
