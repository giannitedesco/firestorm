#ifndef _P_SMB_HEADER_INCLUDED_
#define _P_SMB_HEADER_INCLUDED_

#define SMB_TRANS_REQ		(1<<0)
#define SMB_TRANS_OPLOCK_BREAK	(1<<1)
struct smb_trans {
	uint8_t  flags;
	uint8_t  cmd;
	uint16_t pid;
	uint16_t mid;
};

#define SMB_NUM_TRANS 8
struct smb_flow {
	FILE *file;
	uint8_t cur_trans;
	struct smb_trans trans[SMB_NUM_TRANS];
};

#endif /* _P_SMB_HEADER_INCLUDED_ */
