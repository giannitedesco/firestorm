#ifndef _PKT_SMB_HEADER_INCLUDED_
#define _PKT_SMB_HEADER_INCLUDED_

struct nbss_pkt {
	uint8_t nb_type;
	uint8_t nb_flags;
	uint16_t nb_len;
};

struct smb_pkt {
	uint8_t 	smb_magic[4];
	uint8_t		smb_cmd;
	uint8_t		smb_err_class;
	uint8_t		smb_res;
	uint8_t		smb_err_code[2];
#define SMB_FLAGS_LOCK_AND_READ		(1 << 0)
#define SMB_FLAGS_RECV_BUF_POST		(1 << 1)
#define SMB_FLAGS_IGNORE_CASE		(1 << 3)
#define SMB_FLAGS_CANON_PATH		(1 << 4)
#define SMB_FLAGS_OPLOCKS		(1 << 5)
#define SMB_FLAGS_NOTIFY		(1 << 6)
#define SMB_FLAGS_RESPONSE		(1 << 7)
	uint8_t		smb_flags;
	uint8_t		smb_flags2[2];
	uint8_t		smb_pid_hi[2];
	uint8_t		smb_sig[8];
	uint8_t		smb__pad0[2];
	uint16_t 	smb_tid;	/* Tree ID		*/
	uint16_t 	smb_pid;	/* Process ID		*/
	uint16_t 	smb_uid;	/* User ID		*/
	uint16_t 	smb_mid;	/* Multiplex ID		*/
} _packed;

struct smb_locking_req {
	uint8_t wct;
	uint8_t andx;
	uint8_t _pad0;
	uint16_t andx_ofs;
	uint16_t fid;
#define SMB_LOCK_TYPE_SHARED	(1<<0)
#define SMB_LOCK_TYPE_BREAK	(1<<1)
#define SMB_LOCK_TYPE_CHANGE	(1<<2)
#define SMB_LOCK_TYPE_CANCEL	(1<<3)
#define SMB_LOCK_TYPE_LARGEFILE	(1<<4)
	uint8_t lock_type;
	uint8_t oplock_level;
	uint32_t timeout;
	uint16_t num_unlocks;
	uint16_t num_locks;
	uint16_t bcc;
} _packed;


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

#endif /* _PKT_SMB_HEADER_INCLUDED_ */
