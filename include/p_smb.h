#ifndef _P_SMB_HEADER_INCLUDED_
#define _P_SMB_HEADER_INCLUDED_

#define SMB_PEND_CANCELLED	(1<<0)
struct smb_pend {
	uint8_t  flags;
	uint8_t  cmd;
	uint16_t mid;
	uint32_t pid;
};

#define SMB_MAX_PENDING		128
struct smb_flow {
	FILE *file;
	uint8_t num_trans;
	uint8_t num_trans_live;
	uint8_t num_oplock_break;
#define SMB_DECODE_STATELESS	(1<<0)
#define SMB_DECODE_BALLS_DEEP	(1<<1)
	uint8_t decode_flags;
	struct smb_pend pend[SMB_MAX_PENDING];
};

struct nbss_dcb {
	struct _dcb dcb;
	const struct nbss_pkt *nb;
	char called[17];
	char caller[17];
};

#define SMB_DCB_RESPONSE	(1<<0)
#define SMB_DCB_DONT_TRACK	(1<<1)
struct smb_dcb {
	struct _dcb dcb;
	uint8_t flags; /* same as transaction flags */
	const struct smb_pkt *smb;
	const struct smb_cmd *cmd;
	const uint8_t *payload;
	size_t payload_len;
	const struct smb_pend *pend; /* only valid on responses */
};

#endif /* _P_SMB_HEADER_INCLUDED_ */
