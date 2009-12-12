#ifndef _P_SMTP_HEADER_INCLUDED_
#define _P_SMTP_HEADER_INCLUDED_

#define SMTP_STATE_INIT		0
#define SMTP_STATE_CMD		1
#define SMTP_STATE_RESP		2
#define SMTP_STATE_DATA		3
#define SMTP_STATE_MAX		4

#define SMTP_FLAG_HELO		(1<<0) /* HELO/EHLO was seen */
#define SMTP_FLAG_ESMTP		(1<<1) /* EHLO was seen */
#define SMTP_FLAG_QUIT		(1<<2) /* client must quit */
struct smtp_flow {
	uint8_t state;
	uint8_t flags;
};


#define SMTP_RESP_MULTI		(1<<0) /* multi-line response */
struct smtp_response_dcb {
	struct _dcb dcb;
	uint16_t code;
	uint16_t flags;
	struct ro_vec msg;
};

struct smtp_request_dcb {
	struct _dcb dcb;
	struct ro_vec cmd;
	struct ro_vec str;
};

struct smtp_cont_dcb {
	struct _dcb dcb;
};

#endif /* _P_SMTP_HEADER_INCLUDED_ */
