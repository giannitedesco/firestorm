/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <p_tcp.h>
#include <p_http.h>
#include <f_stream.h>

#include <limits.h>
#include <ctype.h>

#if 0
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do { } while(0);
#define dhex_dump(x...) do { } while(0);
#endif

/* Accepted HTTP versions, must correspond with the  */
static struct {
	int maj, min;
}http_proto_vers[HTTP_VER_MAX]={
	[HTTP_VER_UNKNOWN] {-1, -1},
	[HTTP_VER_0_9] {0, 9},
	[HTTP_VER_1_0] {1, 0},
	[HTTP_VER_1_1] {1, 1},
};

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

/* Get a version code for a given major and minor version */
static inline unsigned int http_vers_idx(int maj, int min)
{
	int i;

	for(i=1; i < HTTP_VER_MAX; i++) {
		if ( http_proto_vers[i].maj == maj &&
			http_proto_vers[i].min == min )
		return i;
	}

	return HTTP_VER_UNKNOWN;
}

/* Parse and HTTP version string (eg: "HTTP/1.0") */
static int http_proto_version(struct ro_vec *str)
{
	const uint8_t *s = str->v_ptr;
	int maj, min;
	int ret;

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
	ret = http_vers_idx(maj, min);

	return ret;
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
				if ( hv[i].v_len && *(cur-1) == '\r' )
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
				if ( v.v_len && *(cur-1)=='\r' ) {
					v.v_len--;
				}
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
static size_t http_req(struct http_dcb *dcb, const uint8_t *ptr, size_t len)
{
	struct http_request_dcb *r = (struct http_request_dcb *)dcb;
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

	/* Fill in other fields */
	r->port = HTTP_DEFAULT_PORT;
	r->proto_vers = http_proto_version(&pv);

	/* Update flow state */
	if ( clen > 0 )
		r->http.content.v_len = clen;

	/* Strip out Request-URI to just abs_path, Filling in host
	 * information if there was no host header
	 */
	if ( !prox ) {
		if ( r->uri.v_len < 7 || memcmp(r->uri.v_ptr, "http://", 7) )
			goto done;
	}

	for(i=state=do_host=0; i < r->uri.v_len; i++) {
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
	if ( r->host.v_ptr ) {
		size_t i;
		struct ro_vec port = { .v_ptr = NULL };
		unsigned int prt;

		for(i=r->host.v_len; i; i--) {
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

static size_t http_resp(struct http_dcb *dcb, const uint8_t *ptr, size_t len)
{
	struct http_response_dcb *r = (struct http_response_dcb *)dcb;
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

static ssize_t parse_req(struct http_flow *f, struct http_fside *fs,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	size_t vb = bytes;
	size_t v, i, b;

	for(b = v = 0; v < numv; v++) {
		for(i = 0; i < vec[v].v_len; i++) {
			if ( vec[v].v_ptr[i] != '\n' )
				continue;
			if ( !check_req(vec, vb, b + i, v, i) ) {
				vb = b + i;
				continue;
			}
			return b + i + 1;
		}
		b += vec[v].v_len;
	}

	return 0;
}

static ssize_t push_hdr(struct _pkt *pkt, struct http_fside *fs,
			struct ro_vec *vec, size_t numv, size_t bytes)
{
	const struct tcpstream_dcb *s;
	struct http_flow *f;
	struct http_dcb *dcb;
	const uint8_t *buf;
	size_t len, hsz;
	ssize_t ret;

	static const struct {
		struct _proto *proto;
		size_t (*parse)(struct http_dcb *d, const uint8_t *p, size_t l);
	}parser[] = {
		[TCP_CHAN_TO_SERVER] = { .proto = &p_http_req,
					 .parse = http_req},
		[TCP_CHAN_TO_CLIENT] = { .proto = &p_http_resp,
					 .parse = http_resp},
	};

	s = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = s->s->flow;

	ret = parse_req(f, fs, vec, numv, bytes);
	if ( ret <= 0 )
		return ret;

	len = (size_t)ret;

	if ( vec[0].v_len < len ) {
		buf = s->reasm(s->sbuf, len);
		if ( NULL == buf )
			return 0;
	}else{
		buf = vec[0].v_ptr;
	}

	dcb = (struct http_dcb *)decode_layer0(pkt, parser[s->chan].proto);
	if ( NULL == dcb )
		return 0;
	hsz = parser[s->chan].parse(dcb, buf, len);

	if ( dcb->content.v_len && len == hsz ) {
		if ( len + dcb->content.v_len <= bytes ) {
			const uint8_t *buf2;

			len = hsz + dcb->content.v_len;
			if ( vec[0].v_len < len ) {
				buf2 = s->reasm(s->sbuf, len);
				if ( NULL == buf2 ) {
					ret = 0;
					goto end;
				}
				hsz = parser[s->chan].parse(dcb, buf2, len);
				dcb->content.v_ptr = buf2 + hsz;
				buf = buf2;
			}else{
				dcb->content.v_ptr = buf + hsz;
			}
		}else{
			if ( dcb->content.v_len > HTTP_MAX_RESP_DATA ) {
				fs->state = HTTP_STATE_CONTENT;
				fs->content_len = dcb->content.v_len;
			}else{
				ret = 0;
			}
		}
	}

	if ( ret > 0 ) {
		pkt->pkt_caplen = pkt->pkt_len = len;
		pkt->pkt_base = buf;
		pkt->pkt_end = pkt->pkt_nxthdr = pkt->pkt_base + pkt->pkt_len;
		pkt_inject(pkt);
	}

end:
	return ret;
}

static ssize_t http_content(struct _pkt *pkt, const uint8_t *ptr, size_t len)
{
	struct http_cont_dcb *dcb;

	dcb = (struct http_cont_dcb *)decode_layer0(pkt, &p_http_cont);
	if ( NULL == dcb )
		return 0;

	pkt->pkt_caplen = pkt->pkt_len = len;
	pkt->pkt_base = ptr;
	pkt->pkt_end = pkt->pkt_nxthdr = pkt->pkt_base + pkt->pkt_len;
	pkt_inject(pkt);

	return pkt->pkt_len;
}

static ssize_t http_push(struct _pkt *pkt, struct ro_vec *vec, size_t numv,
				size_t bytes)
{
	const struct tcpstream_dcb *dcb;
	struct http_flow *f;
	struct http_fside *fs;
	ssize_t ret;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	if ( f->seq & 0x1 ) {
		if ( dcb->chan != TCP_CHAN_TO_CLIENT )
			return 0;
		fs = &f->server;
	}else{
		if ( dcb->chan != TCP_CHAN_TO_SERVER )
			return 0;
		fs = &f->client;
	}

	switch(fs->state) {
	case HTTP_STATE_HEADER:
		ret = push_hdr(pkt, fs, vec, numv, bytes);
		break;
	case HTTP_STATE_CONTENT:
		if ( vec[0].v_len > fs->content_len ) {
			ret = http_content(pkt, vec[0].v_ptr, fs->content_len);
		}else{
			ret = http_content(pkt, vec[0].v_ptr, vec[0].v_len);
		}
		if ( ret <= 0 )
			break;
		fs->content_len -= (size_t)ret;
		if ( 0 == fs->content_len )
			fs->state = HTTP_STATE_HEADER;
		break;
	case HTTP_STATE_CHUNKED:
		ret = bytes;
		break;
	case HTTP_STATE_CLOSING:
		ret = bytes;
		break;
	default:
		ret = bytes;
		assert(0);
	}

	if ( fs->state == HTTP_STATE_HEADER )
		f->seq++;
	return ret;
}

static int flow_init(void *priv)
{
	struct tcp_session *s = priv;
	struct http_flow *f = s->flow;
	f->client.state = HTTP_STATE_HEADER;
	f->server.state = HTTP_STATE_HEADER;
	f->seq = 0;
	return 1;
}

static void flow_fini(void *priv)
{
}


static struct _sdecode sd_http = {
	.sd_label = "http",
	.sd_push = http_push,
	.sd_flow_init = flow_init,
	.sd_flow_fini = flow_fini,
	.sd_flow_sz = sizeof(struct http_flow),
	.sd_max_msg = 8192,
};

static void __attribute__((constructor)) http_ctor(void)
{
	sdecode_add(&sd_http);
	sdecode_register(&sd_http, SNS_TCP, sys_be16(80));
	sdecode_register(&sd_http, SNS_TCP, sys_be16(81));
	sdecode_register(&sd_http, SNS_TCP, sys_be16(3128));
	sdecode_register(&sd_http, SNS_TCP, sys_be16(8080));

	proto_add(&_tcpstream_decoder, &p_http_req);
	proto_add(&_tcpstream_decoder, &p_http_resp);
	proto_add(&_tcpstream_decoder, &p_http_cont);
}
