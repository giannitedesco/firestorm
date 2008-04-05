#ifndef __PKT_HTTP_HEADER_INCLUDED__
#define __PKT_HTTP_HEADER_INCLUDED__

#define HTTP_DEFAULT_PORT	80

#define HTTP_REQUEST		0
#define HTTP_RESPONSE		1

#define HTTPS_HEADER		0
#define HTTPS_CONTENT		1
#define HTTPS_CHUNKED		2
#define HTTPS_CLOSING		3

/* The three version of the HTTP protocol we are expected to understand as
 * required by RFC 2616. Must be in order.
 */
#define HTTP_VER_UNKNOWN	0
#define HTTP_VER_0_9		1
#define HTTP_VER_1_0		2
#define HTTP_VER_1_1		3
#define HTTP_VER_MAX		4

struct http_request {
	uint8_t type;
	uint8_t proto_vers;
	uint16_t port;
	struct fvec uri;
	struct fvec method;
	struct fvec host;
	struct fvec uri_path;
	struct fvec uri_query;
	void *free;
};

struct http_response {
	uint8_t type;
	uint8_t proto_vers;
	int code;
	struct fvec server;
};

struct http_fside {
	size_t len;
	uint16_t state;
};

struct http_flow {
	struct http_fside client;
	struct http_fside server;
};

#endif /* __PKT_HTTP_HEADER_INCLUDED__ */
