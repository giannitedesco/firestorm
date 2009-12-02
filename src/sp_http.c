/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <pkt/tcp.h>
#include <pkt/http.h>
#include <f_stream.h>

#include <limits.h>
#include <ctype.h>

/* Accepted HTTP versions, must correspond with the  */
static struct {
	int maj, min;
}http_proto_vers[HTTP_VER_MAX]={
	[HTTP_VER_UNKNOWN] {-1, -1},
	[HTTP_VER_0_9] {0, 9},
	[HTTP_VER_1_0] {1, 0},
	[HTTP_VER_1_1] {1, 1},
};

/* HTTP Decode Control Block */
struct http_dcb {
	const char *label;
	void (*fn)(struct http_dcb *, struct ro_vec *);
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

static void htype_string(struct http_dcb *h, struct ro_vec *v)
{
	if ( !h->u.vec )
		return;

	h->u.vec->v_ptr = v->v_ptr;
	h->u.vec->v_len = v->v_len;
}

static void htype_present(struct http_dcb *h, struct ro_vec *v)
{
	*h->u.val = 1;
}

static void htype_int(struct http_dcb *h, struct ro_vec *v)
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
static void htype_code(struct http_dcb *h, struct ro_vec *v)
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
static inline void dispatch_hdr(struct http_dcb *d,
				struct ro_vec *k,
				struct ro_vec *v)
{
	for(; d->label; d++) {
		if ( vstrcmp(k, d->label) )
			continue;
		d->fn(d, v);
	}
}

/* Actually parse an HTTP request */
static size_t http_decode_buf(struct http_dcb *d, const uint8_t *p,
				const uint8_t *end)
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
				dispatch_hdr(d+3, &k, &v);
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
static size_t http_request(struct http_request *r,
				const uint8_t *ptr, size_t len)
{
	const uint8_t *end = ptr + len;
	int clen = -1;
	size_t hlen;
	struct ro_vec pv = {0,}, enc = {0,};
	int prox = 0;
	size_t i;
	int state, do_host;
	struct http_dcb dcb[] = {
		{"method", htype_string, {.vec = &r->method}},
		{"uri", htype_string, {.vec = &r->uri}},
		{"protocol", htype_string, {.vec = &pv}},
		{"Host", htype_string , {.vec = &r->host}},
		{"Content-Length", htype_int, {.val = &clen}},
		{"Content-Encoding", htype_string, {.vec = &enc}},
		{"Proxy-Connection", htype_present, {.val = &prox}},
		{NULL,}
	};

	memset(r, 0, sizeof(*r));

	/* Do the decode */
	hlen = http_decode_buf(dcb, ptr, end);
	if ( !hlen )
		return 0;

	/* Fill in other fields */
	r->port = HTTP_DEFAULT_PORT;
	r->proto_vers = http_proto_version(&pv);

	/* Update flow state */
	if ( clen > 0 ) {
		r->content.v_len = clen;
		if ( enc.v_len ) {
			mesg(M_DEBUG, "request: %u bytes '%.*s' encoded",
				clen, enc.v_len, (char *)enc.v_ptr);
		}
	}

	if ( !vstrcmp(&r->method, "POST") ) {
		/** TODO: decode post data... */
	}else if ( !vstrcmp(&r->method, "CONNECT") ) {
		/* TODO: Implement protocol stacking here */
	}

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

static void msg_http_req(struct http_request *r)
{
#if 0
	mesg(M_DEBUG, "%.*s %.*s (host: %.*s:%u)",
			r->method.v_len, r->method.v_ptr,
			r->uri.v_len, r->uri.v_ptr,
			r->host.v_len, r->host.v_ptr,
			r->port);
	if ( r->content.v_ptr )
		hex_dump(r->content.v_ptr, r->content.v_len, 16);
#endif
}

static ssize_t push_req(struct _stream *s, struct http_flow *f,
			struct http_fside *fs,
			struct ro_vec *vec, size_t numv, size_t bytes)
{
	struct http_request r;
	const uint8_t *buf;
	size_t len, hsz;
	int do_free = 0;
	ssize_t ret;

	/* Apparently a new feature in GCC... */
	ret = parse_req(f, fs, vec, numv, bytes);
	if ( ret <= 0 )
		return ret;

	len = (size_t)ret;

	if ( vec[0].v_len < len ) {
		buf = malloc(len);
		if ( NULL == buf )
			return 0;
		ret = s->s_reasm(s, (uint8_t *)buf, len);
		do_free = 1;
	}else{
		buf = vec[0].v_ptr;
	}

	hsz = http_request(&r, buf, len);

	if ( r.content.v_len && len == hsz ) {
		if ( len + r.content.v_len <= bytes ) {
			uint8_t *buf2;

			len = hsz + r.content.v_len;
			if ( vec[0].v_len < len ) {
				buf2 = malloc(len);
				if ( NULL == buf2 ) {
					ret = 0;
					goto end;
				}
				ret = s->s_reasm(s, buf2, len);
				hsz = http_request(&r, buf2, len);
				r.content.v_ptr = buf2 + hsz;
				if ( do_free ) {
					free((void *)buf);
				}
				do_free = 1;
				buf = buf2;
			}
		}else{
			if ( r.content.v_len > HTTP_MAX_RESP_DATA ) {
				fs->state = HTTP_STATE_CONTENT;
				fs->content_len = r.content.v_len;
			}else{
				ret = 0;
			}
		}
	}

	if ( ret > 0 )
		msg_http_req(&r);

end:
	if ( do_free )
		free((void *)buf);

	return ret;
}

static size_t http_response(struct http_response *r,
				const uint8_t *ptr, size_t len)
{
	const uint8_t *end = ptr + len;
	int clen = -1;
	size_t hlen;
	struct ro_vec pv = {0,}, enc = {0,};
	struct http_dcb dcb[] = {
		{"protocol", htype_string, {.vec = &pv}},
		{"code", htype_code, {.u16 = &r->code}},
		{"msg", htype_string, {.vec = NULL}},
		{"Content-Length", htype_int, {.val = &clen}},
		{"Content-Encoding", htype_string, {.vec = &enc}},
		{"Server", htype_string, {.vec = &r->server}},
		{NULL,}
	};

	memset(r, 0, sizeof(*r));

	hlen = http_decode_buf(dcb, ptr, end);
	if ( !hlen )
		return 0;
	
	if ( clen > 0 )
		r->content.v_len = clen;

	r->proto_vers = http_proto_version(&pv);

	return hlen;
}

static void msg_http_resp(struct http_response *r)
{
#if 0
	mesg(M_DEBUG, "HTTP/%3u %.*s", r->code,
			r->server.v_len, r->server.v_ptr);
	if ( r->content.v_ptr )
		hex_dump(r->content.v_ptr, r->content.v_len, 16);
#endif
}

static ssize_t push_resp(struct _stream *s, struct http_flow *f,
			struct http_fside *fs,
			struct ro_vec *vec, size_t numv, size_t bytes)
{
	struct http_response r;
	const uint8_t *buf;
	size_t len, hsz;
	int do_free = 0;
	ssize_t ret;

	/* Apparently a new feature in GCC... */
	ret = parse_req(f, fs, vec, numv, bytes);
	if ( ret <= 0 )
		return ret;

	len = (size_t)ret;

	if ( vec[0].v_len < len ) {
		buf = malloc(len);
		if ( NULL == buf )
			return 0;
		ret = s->s_reasm(s, (uint8_t *)buf, len);
		do_free = 1;
	}else{
		buf = vec[0].v_ptr;
	}

	hsz = http_response(&r, buf, len);

	if ( r.content.v_len && len == hsz ) {
		if ( len + r.content.v_len <= bytes ) {
			uint8_t *buf2;

			len = hsz + r.content.v_len;
			if ( vec[0].v_len < len ) {
				buf2 = malloc(len);
				if ( NULL == buf2 ) {
					ret = 0;
					goto end;
				}
				ret = s->s_reasm(s, buf2, len);
				hsz = http_response(&r, buf2, len);
				r.content.v_ptr = buf2 + hsz;
				if ( do_free ) {
					free((void *)buf);
				}
				do_free = 1;
				buf = buf2;
			}
		}else{
			if ( r.content.v_len > HTTP_MAX_POST_DATA ) {
				fs->state = HTTP_STATE_CONTENT;
				fs->content_len = r.content.v_len;
			}else{
				ret = 0;
			}
		}
	}

	if ( ret > 0 )
		msg_http_resp(&r);

end:
	if ( do_free )
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
		break;
	default:
		return bytes;
	}

	switch(fs->state) {
	case HTTP_STATE_HEADER:
		if ( fs == &f->client )
			ret = push_req(s, f, fs, vec, numv, bytes);
		else
			ret = push_resp(s, f, fs, vec, numv, bytes);
		break;
	case HTTP_STATE_CONTENT:
		if ( bytes > fs->content_len ) {
			ret = fs->content_len;
			fs->content_len = 0;
			fs->state = HTTP_STATE_HEADER;
		}else{
			fs->content_len -= bytes;
			ret = bytes;
		}
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

	return ret;
}

static int flow_init(void *fptr)
{
	struct http_flow *f = fptr;
	f->client.state = HTTP_STATE_HEADER;
	f->server.state = HTTP_STATE_HEADER;
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
