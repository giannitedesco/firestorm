/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2010 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <p_stream.h>

#if 1
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do { } while(0);
#define dhex_dump(x...) do { } while(0);
#endif

/* State machine for incremental HTTP request parse */
#define RSTATE_INITIAL		0
#define RSTATE_CR		1
#define RSTATE_LF		2
#define RSTATE_CRLF		3
#define RSTATE_LFCR		4
#define RSTATE_CRLFCR		5
#define RSTATE_LFLF		6
#define RSTATE_CRLFLF		7
#define RSTATE_LFCRLF		8
#define RSTATE_CRLFCRLF		9

#define RSTATE_NR_NONTERMINAL	RSTATE_LFLF
#define RSTATE_TERMINAL(x)	((x) >= RSTATE_LFLF)

static const uint8_t cr_map[RSTATE_NR_NONTERMINAL] = {
		[RSTATE_INITIAL] = RSTATE_CR,
		[RSTATE_CR] = RSTATE_CR,
		[RSTATE_LF] = RSTATE_LFCR,
		[RSTATE_CRLF] = RSTATE_CRLFCR,
		[RSTATE_LFCR] = RSTATE_CR,
		[RSTATE_CRLFCR] = RSTATE_CR};
static const uint8_t lf_map[RSTATE_NR_NONTERMINAL] = {
		[RSTATE_INITIAL] = RSTATE_LF,
		[RSTATE_CR] = RSTATE_CRLF,
		[RSTATE_LF] = RSTATE_LFLF,
		[RSTATE_CRLF] = RSTATE_CRLFLF,
		[RSTATE_LFCR] = RSTATE_LFCRLF,
		[RSTATE_CRLFCR] = RSTATE_CRLFCRLF};

struct http_msg_state {
	unsigned len;
	uint8_t state;
};

static void http_hdr_ctor(void *priv)
{
	struct http_msg_state *sm = priv;
	sm->len = 0;
	sm->state = RSTATE_INITIAL;
}

static size_t http_hdr_append(void *priv, const uint8_t *buf, size_t len)
{
	struct http_msg_state *sm = priv;
	size_t i;

	for(i = 0; i < len; i++) {
		switch(buf[i]) {
		case '\r':
			assert(sm->state < RSTATE_NR_NONTERMINAL);
			sm->state = cr_map[sm->state];
			break;
		case '\n':
			assert(sm->state < RSTATE_NR_NONTERMINAL);
			sm->state = lf_map[sm->state];
			break;
		default:
			sm->state = RSTATE_INITIAL;
			continue;
		}
		if ( RSTATE_TERMINAL(sm->state) ) {
			mesg(M_DEBUG, "sm_http: got message of %zu bytes\n",
				sm->len + i + 1);
			return sm->len + i + 1;
		}
	}

	sm->len += i;

	mesg(M_DEBUG, "sm_http: %zu bytes, now at %u bytes total", i, sm->len);
	return 0;
}

const struct stream_ops _sm_http_hdr = {
	.sm_state_sz = sizeof(struct http_msg_state),
	.sm_ctor = http_hdr_ctor,
	.sm_append = http_hdr_append,
};
