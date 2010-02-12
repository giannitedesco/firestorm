#ifndef _P_SMB_HEADER_INCLUDED_
#define _P_SMB_HEADER_INCLUDED_

#define SMB_TRANS_REQ		(1<<0)
#define SMB_TRANS_FLIP		(1<<1)
struct smb_trans {
	uint8_t  flags;
	uint8_t  cmd;
	uint16_t pid;
	uint16_t mid;
};

#define SMB_NUM_TRANS 8
struct smb_flow {
	FILE *file;
	uint8_t num_trans;
	uint8_t num_trans_flip;
	uint8_t num_req_stateless;
	uint8_t num_resp_stateless;
	struct smb_trans trans[SMB_NUM_TRANS];
};

struct nbss_dcb {
	struct _dcb dcb;
	const struct nbss_pkt *nb;
	char called[17];
	char caller[17];
};

struct smb_dcb {
	struct _dcb dcb;
	const struct smb_pkt *smb;
	const uint8_t *payload;
	size_t len;
	uint8_t flags; /* same as transaction flags */
};

#endif /* _P_SMB_HEADER_INCLUDED_ */
