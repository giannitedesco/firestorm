#ifndef _P_POP3_HEADER_INCLUDED_
#define _P_POP3_HEADER_INCLUDED_

#define POP3_STATE_INIT		0
#define POP3_STATE_CMD		1
#define POP3_STATE_RESP		2
#define POP3_STATE_RESP_DATA	3
#define POP3_STATE_DATA		4
#define POP3_STATE_MAX		5

struct pop3_flow {
	unsigned int state;
};


struct pop3_response_dcb {
	struct _dcb dcb;
	unsigned int ok;
	struct ro_vec str;
};

struct pop3_request_dcb {
	struct _dcb dcb;
	struct ro_vec cmd;
	struct ro_vec str;
};

struct pop3_cont_dcb {
	struct _dcb dcb;
};

#endif /* _P_POP3_HEADER_INCLUDED_ */
