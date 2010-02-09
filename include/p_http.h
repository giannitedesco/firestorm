#ifndef _P_HTTP_HEADER_INCLUDED_
#define _P_HTTP_HEADER_INCLUDED_

#define HTTP_DEFAULT_PORT	80

#define HTTP_STATE_HEADER	0
#define HTTP_STATE_CONTENT	1
#define HTTP_STATE_CHUNKED	2
#define HTTP_STATE_CLOSING	3

/* The three version of the HTTP protocol we are expected to understand as
 * required by RFC 2616. Must be in order.
 */
#define HTTP_VER_UNKNOWN	0
#define HTTP_VER_0_9		1
#define HTTP_VER_1_0		2
#define HTTP_VER_1_1		3
#define HTTP_VER_MAX		4

#define HTTP_MAX_POST_DATA	1024
#define HTTP_MAX_RESP_DATA	1024

struct http_dcb {
	struct _dcb dcb;
	struct ro_vec transfer_enc;
	struct ro_vec content_type;
	struct ro_vec content_enc;
	struct ro_vec content;
};

struct http_request_dcb {
	struct http_dcb http;
	uint8_t proto_vers;
	uint8_t _pad0;
	uint16_t port;
	struct ro_vec uri;
	struct ro_vec method;
	struct ro_vec host;
	struct ro_vec uri_path;
	struct ro_vec uri_query;
};

struct http_response_dcb {
	struct http_dcb http;
	uint8_t proto_vers;
	uint8_t _pad0;
	uint16_t code;
};

struct http_cont_dcb {
	struct _dcb dcb;
};

struct http_fside {
	uint8_t state;
	uint8_t _pad0;
	uint16_t _pad1;
	size_t content_len;
};

struct http_flow {
	struct http_fside client;
	struct http_fside server;
	unsigned int seq;
};

#endif /* _P_HTTP_HEADER_INCLUDED_ */
