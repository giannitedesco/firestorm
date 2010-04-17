/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
 *
 * TODO:
 *  - interpret session keep-alive/close for 1.0 vs 1.1 connections
 *  - support chunked transfer encoding
 *  - include partial content with req/resp if possible
 *  - incorporate NADS :]
 *  - use htype for host header
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <p_tcp.h>
#include <p_http.h>

#include <limits.h>
#include <ctype.h>

#if 1
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do { } while(0);
#define dhex_dump(x...) do { } while(0);
#endif

static struct _proto p_http_req = {
	.p_label = "http_request",
	.p_dcb_sz = sizeof(struct http_request_dcb),
};

static struct _proto p_http_resp = {
	.p_label = "http_response",
	.p_dcb_sz = sizeof(struct http_response_dcb),
};

static struct _proto p_http_cont = {
	.p_label = "http_cont",
	.p_dcb_sz = sizeof(struct http_cont_dcb),
};

/* HTTP Decode Control Block */
struct http_hcb {
	const char *label;
	void (*fn)(struct http_hcb *, struct ro_vec *);
	union {
		struct ro_vec *vec;
		uint16_t *u16;
		int *val;
	}u;
};

/* Parse and HTTP version string (eg: "HTTP/1.0") */
static int http_proto_version(struct ro_vec *str)
{
	const uint8_t *s = str->v_ptr;
	int maj, min;

	if ( str->v_ptr == NULL )
		return HTTP_VER_UNKNOWN;

	if ( str->v_len != 8 ) /* sizeof("HTTP/X.Y") */
		return HTTP_VER_UNKNOWN;

	if ( memcmp(s, "HTTP/", 5) )
		return HTTP_VER_UNKNOWN;

	if ( s[6] != '.' )
		return HTTP_VER_UNKNOWN;

	if ( !isdigit(s[5]) || !isdigit(s[7]) )
		return HTTP_VER_UNKNOWN;

	maj = s[5] - '0';
	min = s[7] - '0';

	return (min << 4) | maj;
}

static void htype_string(struct http_hcb *h, struct ro_vec *v)
{
	if ( !h->u.vec )
		return;

	h->u.vec->v_ptr = v->v_ptr;
	h->u.vec->v_len = v->v_len;
}

static void htype_present(struct http_hcb *h, struct ro_vec *v)
{
	*h->u.val = 1;
}

static void htype_int(struct http_hcb *h, struct ro_vec *v)
{
	unsigned int val;
	size_t len;

	len = vtouint(v, &val);
	if ( !len || val > INT_MAX ) {
		*h->u.val = -1;
	}else{
		*h->u.val = val;
	}
}

/* Same as int but ensure input is only 3 digits */
static void htype_code(struct http_hcb *h, struct ro_vec *v)
{
	unsigned int val;
	size_t len;

	len = vtouint(v, &val);
	if ( len != 3 || val > 999 )
		*h->u.u16 = 0xffff;
	else
		*h->u.u16 = val;
}

/* Check if this header is one we want to store */
static inline void dispatch_hdr(struct http_hcb *dcb,
				size_t num_dcb,
				struct ro_vec *k,
				struct ro_vec *v)
{
	unsigned int n;
	struct http_hcb *d;

	for(n = num_dcb, d = dcb; n; ) {
		unsigned int i;
		int ret;

		i = (n / 2);
		ret = vstrcmp(k, d[i].label);
		if ( ret < 0 ) {
			n = i;
		}else if ( ret > 0 ) {
			d = d + (i + 1);
			n = n - (i + 1);
		}else{
			d[i].fn(&d[i], v);
			break;
		}
	}
}

/* Actually parse an HTTP request */
static size_t http_decode_buf(struct http_hcb *d, size_t num_dcb,
				const uint8_t *p, const uint8_t *end)
{
	const uint8_t *cur;
	struct ro_vec hv[3]; /* method, url, proto */
	struct ro_vec k,v;
	int i = 0;
	int state = 0;
	int ret = 0;

	hv[0].v_len = 0;
	hv[1].v_len = 0;
	hv[2].v_len = 0;

	for(cur = p; cur < end; cur++) {
		switch ( state ) {
		case 0:
			if ( *cur != ' ' ) {
				state = 1;
				hv[i].v_ptr = (void *)cur;
				hv[i].v_len = 0;
			}
			break;
		case 1:
			hv[i].v_len++;
			switch(*cur) {
			case ' ':
				if ( i<2 ) {
					state = 0;
					i++;
				}
				break;
			case '\n':
				if ( hv[i].v_len && *(cur - 1) == '\r' )
					hv[i].v_len--;
				k.v_ptr = (void *)cur + 1;
				k.v_len = 0;
				state = 2;
				ret = (cur - p) + 1;
				break;
			}
			break;
		case 2:
			if ( *cur == ':' ) {
				state = 3;
				break;
			}else if ( *cur == '\n' ) {
				ret = (cur - p) + 1;
				cur = end;
			}
			k.v_len++;
			break;
		case 3:
			if ( *cur != ' ' ) {
				v.v_ptr = (void *)cur;
				v.v_len = 0;
				state = 4;
			}
			break;
		case 4:
			v.v_len++;
			if ( *cur == '\n' ) {
				if ( v.v_len && *(cur-1) == '\r' )
					v.v_len--;
				dispatch_hdr(d + 3, num_dcb - 3, &k, &v);
				k.v_ptr = (void *)cur + 1;
				k.v_len = 0;
				state = 2;
				break;
			}
			break;
		}
	}

	if ( !hv[0].v_len || !hv[1].v_len )
		return 0;

	/* Setup method/url/proto */
	d[0].fn(&d[0], &hv[0]);
	d[1].fn(&d[1], &hv[1]);
	d[2].fn(&d[2], &hv[2]);

	return ret;
}

/* Parse an HTTP request header and fill in the http response structure */
static size_t http_req(struct http_request_dcb *dcb,
			const uint8_t *ptr, size_t len)
{
	struct http_request_dcb *r = dcb;
	const uint8_t *end = ptr + len;
	int clen = -1;
	size_t hlen;
	struct ro_vec pv = {0,};
	int prox = 0;
	size_t i;
	int state, do_host;
	struct http_hcb hcb[] = {
		{"method", htype_string, {.vec = &r->method}},
		{"uri", htype_string, {.vec = &r->uri}},
		{"protocol", htype_string, {.vec = &pv}},
		{"Host", htype_string , {.vec = &r->host}},
		{"Content-Type", htype_string,
					{.vec = &r->http.content_type}},
		{"Content-Length", htype_int, {.val = &clen}},
		{"Proxy-Connection", htype_present, {.val = &prox}},
		{"Content-Encoding", htype_string,
					{.vec = &r->http.content_enc}},
		{"Transfer-Encoding", htype_string,
					{.vec = &r->http.transfer_enc}},
	};

	/* Do the decode */
	hlen = http_decode_buf(hcb, sizeof(hcb)/sizeof(*hcb), ptr, end);
	if ( !hlen )
		return 0;

	r->proto_vers = http_proto_version(&pv);

	if ( clen > 0 )
		r->http.content.v_len = clen;

	/* Strip out Request-URI to just abs_path, Filling in host
	 * information if there was no host header
	 */
	if ( !prox ) {
		if ( r->uri.v_len < 7 ||
			strncasecmp((const char *)r->uri.v_ptr, "http://", 7) )
			goto done;
	}

	for(i = state = do_host = 0; i < r->uri.v_len; i++) {
		if ( state == 0 ) {
			if ( ((char *)r->uri.v_ptr)[i] == ':' )
				state++;
		}else if ( state >= 1 && state < 4 ) {
			if ( ((char *)r->uri.v_ptr)[i] == '/' ) {
				if ( state == 3 && !r->host.v_ptr ) {
					r->host.v_ptr = r->uri.v_ptr + i + 1;
					r->host.v_len = 0;
					do_host = 1;
				}
				state++;
			}else if ( do_host ) {
				r->host.v_len++;
			}
		}else{
			i -= 1;
			break;
		}
	}

	if ( state < 3 )
		goto done;

	r->uri.v_ptr += i;
	r->uri.v_len -= i;

	if ( r->uri.v_len == 0 )
		r->uri.v_ptr = NULL;

done:
	/* Extract the port from the host header */
	r->port = HTTP_DEFAULT_PORT;
	if ( r->host.v_ptr ) {
		size_t i;
		struct ro_vec port = { .v_ptr = NULL };
		unsigned int prt;

		for(i = r->host.v_len; i; i--) {
			if (  ((uint8_t *)r->host.v_ptr)[i-1] == ':' ) {
				port.v_len = r->host.v_len - i;
				port.v_ptr = r->host.v_ptr + i;
				r->host.v_len = i - 1;
				break;
			}
		}

		if ( port.v_len ) {
			if ( vtouint(&port, &prt) == port.v_len ) {
				if ( prt & ~0xffffUL ) {
					/* TODO */
					//alert_tag(p, &a_invalid_port, -1);
				}else{
					r->port = prt;
				}
			}
		}
	}

	/* rfc2616: An empty abs_path is equivalent to an abs_path of "/" */
	if ( r->uri.v_ptr == NULL ) {
		r->uri.v_ptr = (const uint8_t *)"/";
		r->uri.v_len = 1;
	}

	return hlen;
}

static size_t http_resp(struct http_response_dcb *dcb,
				const uint8_t *ptr, size_t len)
{
	struct http_response_dcb *r = dcb;
	const uint8_t *end = ptr + len;
	int clen = -1;
	size_t hlen;
	struct ro_vec pv = {0,};
	struct http_hcb hcb[] = {
		{"protocol", htype_string, {.vec = &pv}},
		{"code", htype_code, {.u16 = &r->code}},
		{"msg", htype_string, {.vec = NULL}},
		{"Content-Type", htype_string, {.vec = &r->http.content_type}},
		{"Content-Length", htype_int, {.val = &clen}},
		{"Content-Encoding", htype_string,
					{.vec = &r->http.content_enc}},
		{"Transfer-Encoding", htype_string,
					{.vec = &r->http.transfer_enc}},
	};

	hlen = http_decode_buf(hcb, sizeof(hcb)/sizeof(*hcb), ptr, end);
	if ( !hlen )
		return 0;

	if ( clen > 0 )
		r->http.content.v_len = clen;

	r->proto_vers = http_proto_version(&pv);

	return hlen;
}

static void decode_hdr(const struct http_flow *f, const struct http_fside *fs,
			struct _pkt *pkt)
{
	struct http_dcb *dcb;
	const struct tcpstream_dcb *tcp_dcb;
	size_t hlen, clen;

	tcp_dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;

	//hex_dump(pkt->pkt_base, pkt->pkt_len, 16);
	if ( tcp_dcb->chan == TCP_CHAN_TO_SERVER ) {
		dcb = (struct http_dcb *)decode_layer0(pkt, &p_http_req);
		hlen = http_req((struct http_request_dcb *)dcb,
				pkt->pkt_base, pkt->pkt_len);
	}else{
		dcb = (struct http_dcb *)decode_layer0(pkt, &p_http_resp);
		hlen = http_resp((struct http_response_dcb *)dcb,
				pkt->pkt_base, pkt->pkt_len);
	}

	if ( 0 == hlen ) {
		pkt->pkt_len = 0;
		return;
	}

	clen = dcb->content.v_len;
	if ( pkt->pkt_len < hlen + clen && hlen + clen <= pkt->pkt_caplen ) {
		pkt->pkt_len = hlen + clen;
		return;
	}

	if ( clen && hlen + clen <= pkt->pkt_len ) {
		pkt->pkt_len = hlen + clen;
		dcb->content.v_ptr = pkt->pkt_base + hlen;
	}else{
		pkt->pkt_len = hlen;
	}
}

static void decode_content(const struct http_flow *f,
				const struct http_fside *fs,
				struct _pkt *pkt)
{
	const struct tcpstream_dcb *tcp_dcb;
	struct http_cont_dcb *dcb;

	assert(pkt->pkt_len <= fs->content_len);

	tcp_dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = (struct http_cont_dcb *)decode_layer0(pkt, &p_http_cont);

	dmesg(M_DEBUG, "http: %s %u/%u bytes of content",
		((tcp_dcb->chan) == TCP_CHAN_TO_SERVER) ? ">>>" : "<<<",
		pkt->pkt_len, fs->content_len);
}

static void http_decode(struct _pkt *pkt)
{
	const struct tcpstream_dcb *tcp_dcb;
	const struct http_flow *f;
	const struct http_fside *fs;

	tcp_dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;

	f = tcp_sesh_get_flow(tcp_dcb->sesh);
	if ( f->seq & 0x1 ) {
		assert(tcp_dcb->chan == TCP_CHAN_TO_CLIENT);
		fs = &f->server;
	}else{
		assert(tcp_dcb->chan == TCP_CHAN_TO_SERVER);
		fs = &f->client;
	}

	//dmesg(M_WARN, "http: pkt %u/%u bytes", pkt->pkt_len, pkt->pkt_caplen);
	//hex_dump(pkt->pkt_base, pkt->pkt_len, 16);

	switch(fs->state) {
	case HTTP_STATE_HEADER:
		decode_hdr(f, fs, pkt);
		break;
	case HTTP_STATE_CONTENT:
		decode_content(f, fs, pkt);
		break;
	case HTTP_STATE_CHUNKED:
	case HTTP_STATE_CLOSING:
		dmesg(M_WARN, "TODO");
		pkt->pkt_len = 0;
		break;
	default:
		dmesg(M_CRIT, "http: corrupt flow");
		pkt->pkt_len = 0;
		break;
	}
}

static void http_update_seq(tcp_sesh_t sesh, struct http_flow *f)
{
	if ( ++f->seq & 0x1 )
		tcp_sesh_wait(sesh, TCP_CHAN_TO_CLIENT);
	else
		tcp_sesh_wait(sesh, TCP_CHAN_TO_SERVER);
}

static void state_update_hdr(struct http_flow *f, struct http_fside *fs,
					struct _pkt *pkt)
{
	const struct tcpstream_dcb *tcp_dcb;
	const struct http_dcb *dcb;

	tcp_dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = (const struct http_dcb *)tcp_dcb->dcb.dcb_next;

	assert(dcb->dcb.dcb_proto == &p_http_req ||
		dcb->dcb.dcb_proto == &p_http_resp);

	if ( dcb->content.v_len && NULL == dcb->content.v_ptr ) {
		fs->state = HTTP_STATE_CONTENT;
		fs->content_len = dcb->content.v_len;
	}else{
		fs->state = HTTP_STATE_HEADER;
		http_update_seq(tcp_dcb->sesh, f);
	}

	if ( dcb->dcb.dcb_proto == &p_http_req) {
		const struct http_request_dcb *r;

		r = (struct http_request_dcb *)dcb;
		dmesg(M_DEBUG, "http: >>> %.*s %.*s:%u %.*s",
			r->method.v_len, r->method.v_ptr,
			r->host.v_len, r->host.v_ptr, r->port,
			r->uri.v_len, r->uri.v_ptr);
		if ( r->http.content.v_len )
			dmesg(M_DEBUG, "http: >>> %u bytes of %.*s",
				r->http.content.v_len,
				r->http.content_type.v_len,
				r->http.content_type.v_ptr);
		if ( !r->http.content_enc.v_len &&
				!r->http.transfer_enc.v_len )
			return;
		dmesg(M_DEBUG, "http: >>>  encoding content=%.*s transfer=%.*s",
			r->http.content_enc.v_len,
			r->http.content_enc.v_ptr,
			r->http.transfer_enc.v_len,
			r->http.transfer_enc.v_ptr);
	}else{
		const struct http_response_dcb *r;

		r = (struct http_response_dcb *)dcb;
		dmesg(M_DEBUG, "http: <<< HTTP/%u - %u bytes %.*s",
			r->code, r->http.content.v_len,
			r->http.content_type.v_len,
			r->http.content_type.v_ptr);
		if ( !r->http.content_enc.v_len &&
				!r->http.transfer_enc.v_len )
			return;
		dmesg(M_DEBUG, "http: <<<  encoding content=%.*s transfer=%.*s",
			r->http.content_enc.v_len,
			r->http.content_enc.v_ptr,
			r->http.transfer_enc.v_len,
			r->http.transfer_enc.v_ptr);
	}
	if ( dcb->content.v_ptr )
		hex_dump(dcb->content.v_ptr, dcb->content.v_len, 16);
}

static void state_update_content(struct http_flow *f, struct http_fside *fs,
					struct _pkt *pkt)
{
	const struct tcpstream_dcb *tcp_dcb;
	const struct http_cont_dcb *dcb;

	tcp_dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = (const struct http_cont_dcb *)tcp_dcb->dcb.dcb_next;

	assert(dcb->dcb.dcb_proto == &p_http_cont);

	fs->content_len -= pkt->pkt_len;
	if ( 0 == fs->content_len ) {
		fs->state = HTTP_STATE_HEADER;
		http_update_seq(tcp_dcb->sesh, f);
	}
}

static void state_update(tcp_sesh_t sesh, tcp_chan_t chan, struct _pkt *pkt)
{
	struct http_flow *f;
	struct http_fside *fs;

	f = tcp_sesh_get_flow(sesh);
	if ( f->seq & 0x1 ) {
		assert(chan & TCP_CHAN_TO_CLIENT);
		chan = TCP_CHAN_TO_CLIENT;
		fs = &f->server;
	}else{
		assert(chan & TCP_CHAN_TO_SERVER);
		chan = TCP_CHAN_TO_SERVER;
		fs = &f->client;
	}

	switch(fs->state) {
	case HTTP_STATE_HEADER:
		state_update_hdr(f, fs, pkt);
		break;
	case HTTP_STATE_CONTENT:
		state_update_content(f, fs, pkt);
		break;
	case HTTP_STATE_CHUNKED:
	case HTTP_STATE_CLOSING:
		dmesg(M_WARN, "TODO");
		break;
	}
}

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
static inline int http_parse_incremental(uint8_t *state,
					const uint8_t **rptr,
					const uint8_t *end)
{
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

	assert(end >= *rptr);

	for(; *rptr < end; (*rptr)++) {
		switch((*rptr)[0]) {
		case '\r':
			assert((*state) < RSTATE_NR_NONTERMINAL);
			(*state) = cr_map[(*state)];
			break;
		case '\n':
			assert((*state) < RSTATE_NR_NONTERMINAL);
			(*state) = lf_map[(*state)];
			break;
		default:
			(*state) = RSTATE_INITIAL;
			continue;
		}
		if ( RSTATE_TERMINAL((*state)) ) {
			(*rptr)++;
			return 1;
		}
	}

	return 0;
}

static ssize_t parse_req(const struct ro_vec *vec, size_t numv, size_t bytes)
{
	uint8_t state = RSTATE_INITIAL;
	size_t b, i;

	for(b = i = 0; i < numv; i++) {
		const uint8_t *rptr, *end;

		rptr = vec[i].v_ptr;
		end = rptr + vec[i].v_len;
		if ( !http_parse_incremental(&state, &rptr, end) ) {
			b += vec[i].v_len;
			continue;
		}

		return b + (rptr - vec[i].v_ptr);
	}

	return 0;
}

static int do_push_hdr(tcp_sesh_t sesh, tcp_chan_t chan)
{
	const struct ro_vec *vec;
	size_t numv, bytes;
	ssize_t ret;

	vec = tcp_sesh_get_buf(sesh, chan, &numv, &bytes);
	if ( NULL == vec )
		return 0;

	//dmesg(M_WARN, "http: got %u bytes in %u vectors", bytes, numv);

	ret = parse_req(vec, numv, bytes);
	if ( ret <= 0 )
		return (int)ret;

	bytes = tcp_sesh_inject(sesh, chan, ret);
	if ( 0 == bytes )
		return 0;

	return 1;
}

static int do_push_content(tcp_sesh_t sesh, tcp_chan_t chan)
{
	const struct http_flow *f;
	const struct http_fside *fs;
	size_t bytes;

	f = tcp_sesh_get_flow(sesh);
	if ( f->seq & 0x1 ) {
		assert(chan == TCP_CHAN_TO_CLIENT);
		fs = &f->server;
	}else{
		assert(chan == TCP_CHAN_TO_SERVER);
		fs = &f->client;
	}

	bytes = tcp_sesh_get_bytes(sesh, chan);
	if ( fs->content_len < bytes )
		bytes = tcp_sesh_inject(sesh, chan, fs->content_len);
	else
		bytes = tcp_sesh_inject(sesh, chan, bytes);

	if ( !bytes )
		return 0;

	return 1;
}

static int push(tcp_sesh_t sesh, tcp_chan_t chan)
{
	const struct http_flow *f;
	const struct http_fside *fs;

	f = tcp_sesh_get_flow(sesh);

	if ( f->seq & 0x1 ) {
		assert(chan & TCP_CHAN_TO_CLIENT);
		chan = TCP_CHAN_TO_CLIENT;
		fs = &f->server;
	}else{
		assert(chan & TCP_CHAN_TO_SERVER);
		chan = TCP_CHAN_TO_SERVER;
		fs = &f->client;
	}

	switch(fs->state) {
	case HTTP_STATE_HEADER:
		return do_push_hdr(sesh, chan);
	case HTTP_STATE_CONTENT:
		return do_push_content(sesh, chan);
	case HTTP_STATE_CHUNKED:
	case HTTP_STATE_CLOSING:
		dmesg(M_WARN, "TODO");
		return 0;
	default:
		dmesg(M_CRIT, "http: corrupt flow");
		return -1;
	}
}

static objcache_t flow_cache;

static int shutdown(tcp_sesh_t sesh, tcp_chan_t chan)
{
	return 1;
}

static int init(tcp_sesh_t sesh)
{
	struct http_flow *f;

	f = objcache_alloc(flow_cache);
	if ( NULL == f )
		return 0;

	dmesg(M_DEBUG, "http_init");
	f->client.state = HTTP_STATE_HEADER;
	f->server.state = HTTP_STATE_HEADER;
	f->seq = 0;

	tcp_sesh_set_flow(sesh, f);
	tcp_sesh_wait(sesh, TCP_CHAN_TO_SERVER);
	return 1;
}

static void fini(tcp_sesh_t sesh)
{
	struct http_flow *f;

	f = tcp_sesh_get_flow(sesh);
	if ( NULL == f )
		return;

	dmesg(M_DEBUG, "http_fini");
	objcache_free2(flow_cache, f);
}

static int http_flow_ctor(void)
{
	flow_cache = objcache_init(NULL, "http_flows",
					sizeof(struct http_flow));
	if ( NULL == flow_cache )
		return 0;

	return 1;
}

static void http_flow_dtor(void)
{
	objcache_fini(flow_cache);
}

static struct _decoder http_decoder = {
	.d_decode = http_decode,
	.d_flow_ctor = http_flow_ctor,
	.d_flow_dtor = http_flow_dtor,
	.d_label = "http",
};

static struct tcp_app http_app = {
	.a_push = push,
	.a_state_update = state_update,
	.a_shutdown = shutdown,
	.a_init = init,
	.a_fini = fini,
	.a_decode = &http_decoder,
	.a_label = "http",
};

static void __attribute__((constructor)) http_ctor(void)
{
	decoder_add(&http_decoder);
	proto_add(&http_decoder, &p_http_req);
	proto_add(&http_decoder, &p_http_resp);
	proto_add(&http_decoder, &p_http_cont);

	tcp_app_register(&http_app);
	tcp_app_register_dport(&http_app, 80);
	tcp_app_register_dport(&http_app, 8080);
	tcp_app_register_dport(&http_app, 8081);
	tcp_app_register_dport(&http_app, 3128);
}
