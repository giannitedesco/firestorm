#ifndef _PKT_SMB_HEADER_INCLUDED_
#define _PKT_SMB_HEADER_INCLUDED_

#define SMB_NUM_TRANS 8
struct smb_flow {
	FILE *file;
	uint8_t cur_trans;
	struct smb_trans trans[SMB_NUM_TRANS];
};

#endif /* _PKT_SMB_HEADER_INCLUDED_ */
