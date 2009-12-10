/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <pkt/tcp.h>
#include <pkt/pop3.h>
#include <f_stream.h>

#include <limits.h>
#include <ctype.h>

#if 1
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do { } while(0);
#define dhex_dump(x...) do { } while(0);
#endif

static int parse_response(struct pop3_response *r, struct ro_vec *v)
{
	const uint8_t *ptr, *end;

	if ( v->v_len < 1 )
		return 0;

	switch(v->v_ptr[0]) {
	case '+':
		r->ok = 1;
		break;
	case '-':
		r->ok = 0;
		break;
	default:
		return 0;
	}

	ptr = v->v_ptr + 1;
	end = v->v_ptr + v->v_len;
	while(ptr < end && !isspace(*ptr))
		ptr++;
	while(ptr < end && isspace(*ptr))
		ptr++;

	r->str.v_len = end - ptr;
	r->str.v_ptr = (r->str.v_len) ? ptr : NULL;
	return 1;
}

static int do_response(struct _stream *s, struct pop3_flow *f, struct ro_vec *v)
{
	struct pop3_response r;

	switch(f->state) {
	case POP3_STATE_INIT:
	case POP3_STATE_RESP:
	case POP3_STATE_RESP_DATA:
		break;
	case POP3_STATE_DATA:
		if ( v->v_len == 1 && v->v_ptr[0] == '.' ) {
			f->state = POP3_STATE_CMD;
		}
		return 1;
	default:
		return 1;
	}

	if ( !parse_response(&r, v) ) {
		mesg(M_ERR, "pop3: response: %.*s", v->v_len, v->v_ptr);
		return 1;
	}

	//dmesg(M_DEBUG, "<<< %s %.*s",
	//	(r.ok) ? "OK" : "ERR",
	//	r.str.v_len, r.str.v_ptr);

	if ( f->state == POP3_STATE_RESP_DATA && r.ok ) {
		f->state = POP3_STATE_DATA;
	}else{
		f->state = POP3_STATE_CMD;
	}

	return 1;
}

struct pop3_cmd {
	struct ro_vec cmd;
	void(*fn)(struct _stream *s, struct pop3_request *r);
};

static const struct pop3_cmd cmds[] = {
	{ .cmd = {.v_ptr = (uint8_t *)"TOP", .v_len = 3}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"APOP", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"DELE", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"LIST", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"NOOP", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"PASS", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"QUIT", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"RETR", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"RSET", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"STAT", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"UIDL", .v_len = 4}, .fn = NULL },
	{ .cmd = {.v_ptr = (uint8_t *)"USER", .v_len = 4}, .fn = NULL },
};

static void dispatch_req(struct _stream *s, struct pop3_request *r)
{
	const struct pop3_cmd *c;
	unsigned int n;

	for(n = sizeof(cmds)/sizeof(*cmds), c = cmds; n; ) {
		unsigned int i;
		int ret;

		i = (n / 2);
		ret = vcasecmp(&r->cmd, &c[i].cmd);
		if ( ret < 0 ) {
			n = i;
		}else if ( ret > 0 ) {
			c = c + (i + 1);
			n = n - (i + 1);
		}else{
			if ( c[i].fn )
				c[i].fn(s, r);
			break;
		}
	}

	//dmesg(M_DEBUG, ">>> %.*s %.*s",
	//	r->cmd.v_len, r->cmd.v_ptr,
	//	r->str.v_len, r->str.v_ptr);
}

static int parse_request(struct _stream *s, struct pop3_request *r,
				struct ro_vec *v)
{
	const uint8_t *ptr, *end;

	if ( v->v_len < 4 )
		return 0;

	r->cmd.v_ptr = v->v_ptr;
	r->cmd.v_len = 0;

	for(ptr = v->v_ptr, end = v->v_ptr + v->v_len; ptr < end; ptr++) {
		if ( isspace(*ptr) )
			break;
		r->cmd.v_len++;
	}
	for(; ptr < end && isspace(*ptr); ptr++)
		/* nothing */;

	r->str.v_len = end - ptr;
	r->str.v_ptr = (r->str.v_len) ? ptr : NULL;

	dispatch_req(s, r);
	return 1;
}

static int do_request(struct _stream *s, struct pop3_flow *f, struct ro_vec *v)
{
	struct pop3_request r;
	struct ro_vec data = {
		.v_ptr = (uint8_t *)"RETR",
		.v_len = 4,
	};

	if ( f->state != POP3_STATE_CMD )
		return 0;

	if ( !parse_request(s, &r, v) ) {
		mesg(M_ERR, "pop3: request: %.*s", v->v_len, v->v_ptr);
		return 1;
	}

	if ( vcasecmp(&data, &r.cmd) ) {
		f->state = POP3_STATE_RESP;
	}else{
		f->state = POP3_STATE_RESP_DATA;
	}
	return 1;
}

static int pop3_line(struct _stream *s, struct pop3_flow *f,
			schan_t chan, const uint8_t *ptr, size_t len)
{
	struct ro_vec vec;

	assert(f->state < POP3_STATE_MAX);

	vec.v_ptr = ptr;
	vec.v_len = len;

	switch(chan) {
	case TCP_CHAN_TO_CLIENT:
		return do_response(s, f, &vec);
	case TCP_CHAN_TO_SERVER:
		return do_request(s, f, &vec);
	default:
		break;
	}

	return 1;
}

static ssize_t pop3_push(struct _stream *s, schan_t chan,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	struct pop3_flow *f;
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

	if ( !pop3_line(s, f, chan, buf, sz) )
		ret = 0;

	if ( do_free )
		free((void *)buf);

	return ret;
}

static int flow_init(struct _stream *s)
{
	struct pop3_flow *f = s->s_flow;
	f->state = POP3_STATE_INIT;
	return 1;
}

static void flow_fini(struct _stream *s)
{
}


static struct _sproto sp_pop3 = {
	.sp_label = "pop3",
	.sp_flow_init = flow_init,
	.sp_flow_fini = flow_fini,
	.sp_flow_sz = sizeof(struct pop3_flow),
};

static struct _sdecode sd_pop3 = {
	.sd_label = "pop3",
	.sd_push = pop3_push,
	.sd_max_msg = 1024,
};

static void __attribute__((constructor)) pop3_ctor(void)
{
	sproto_add(&sp_pop3);
	sdecode_add(&sp_pop3, &sd_pop3);
	sdecode_register(&sd_pop3, SNS_TCP, sys_be16(110));
}
