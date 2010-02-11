#ifndef _PKT_SMB_HEADER_INCLUDED_
#define _PKT_SMB_HEADER_INCLUDED_

struct nbss_pkt {
#define NBSS_SESSION_MSG		0x00
#define NBSS_SESSION_SETUP		0x81
#define NBSS_SESSION_SETUP_OK		0x82
#define NBSS_SESSION_SETUP_ERR		0x83
#define NBSS_SESSION_RETARGET		0x84
#define NBSS_SESSION_KEEPALIVE		0x85
	uint8_t nb_type;
	uint8_t nb_flags;
	uint16_t nb_len;
	union {
		struct {
			uint8_t		called[34];
			uint8_t		caller[34];
		}setup;
		struct {
			uint8_t		code;
		}err;
		struct {
			uint32_t	ip;
			uint16_t	port;
		}retarget _packed;
	}nb_u[0];
} _packed;

#define NBSS_ERR_CALLED_NAME		0x80
#define NBSS_ERR_CALLING_NAME		0x81
#define NBSS_ERR_NAME_NOT_PRESENT	0x82
#define NBSS_ERR_RESOURCE		0x83
#define NBSS_ERR_UNSPECIFIED		0xdff

/* SMB Core Commands */
#define SMB_MKDIR			0x00
#define SMB_RMDIR			0x01
#define SMB_OPEN			0x02
#define SMB_CREATE			0x03
#define SMB_CLOSE			0x04
#define SMB_FLUSH			0x05
#define SMB_DELETE			0x06
#define SMB_RENAME			0x07
#define SMB_GET_INFO			0x08
#define SMB_SET_INFO			0x09
#define SMB_READ			0x0a
#define SMB_WRITE			0x0b
#define SMB_LOCK			0x0c
#define SMB_UNLOCK			0x0d
#define SMB_CREATE_TEMP			0x0e
#define SMB_CREATE_NEW			0x0f
#define SMB_CHECK_DIRECTORY		0x10
#define SMB_PROCESS_EXIT		0x11
#define SMB_SEEK			0x12
#define SMB_LOCK_READ			0x13
#define SMB_WRITE_UNLOCK		0x14
#define SMB_READ_RAW			0x1a
#define SMB_READ_BLOCK_MPX		0x1b
#define SMB_READ_BLOCK_S		0x1c
#define SMB_WRITE_RAW			0x1d
#define SMB_WRITE_BLOCK_MPX		0x1e
#define SMB_WRITE_BLOCK_S		0x1f
#define SMB_WRITE_COMPLETE		0x20
#define SMB_SET_INFO2			0x22
#define SMB_GET_INFO2			0x23
#define SMB_LOCKING_ANDX		0x24
#define SMB_TRANS			0x25
#define SMB_TRANS_S			0x26
#define SMB_IOCTL			0x27
#define SMB_IOCTL_S			0x28
#define SMB_COPY			0x29
#define SMB_MOVE			0x2a
#define SMB_ECHO			0x2b
#define SMB_WRITE_CLOSE			0x2c
#define SMB_OPEN_ANDX			0x2d
#define SMB_READ_ANDX			0x2e
#define SMB_WRITE_ANDX			0x2f
#define SMB_TRANS2			0x32
#define SMB_TRANS2_S			0x33
#define SMB_FIND_CLOSE2			0x34
#define SMB_FIND_NOTIFY_CLOSE		0x35
#define SMB_TREE_CONNECT		0x70
#define SMB_TREE_DISCONNECT		0x71
#define SMB_NEG_PROT			0x72
#define SMB_SESSION_SETUP_ANDX		0x73
#define SMB_LOGOFF_ANDX			0x74
#define SMB_TREE_CONNECT_ANDX		0x75
#define SMB_GET_INFO_DISK		0x80
#define SMB_SEARCH			0x81
#define SMB_FIND			0x82
#define SMB_FIND_UNIQUE			0x83
#define SMB_FIND_CLOSE			0x84
#define SMB_NT_TRANS			0xa0
#define SMB_NT_TRANS_S			0xa1
#define SMB_NT_CREATE_ANDX		0xa2
#define SMB_NT_CANCEL			0xa4
#define SMB_NT_RENAME			0xa5
#define SMB_SPOOL_OPEN			0xc0
#define SMB_SPOOL_LOCK			0xc1
#define SMB_SPOOL_CLOSE			0xc2
#define SMB_SPOOL_RETQ			0xc3
#define SMB_SENDS			0xd0
#define SMB_SENDB			0xd1
#define SMB_FWD_NAME			0xd2
#define SMB_CANCEL_FWD			0xd3
#define SMB_GETMAC			0xd4
#define SMB_SEND_START			0xd5
#define SMB_SEND_TEXT			0xd6
#define SMB_READ_BULK			0xd8
#define SMB_WRITE_BULK			0xd9
#define SMB_WRITE_BULK_DATA		0xda

struct smb_pkt {
#define SMB_MAGIC			"\xffSMB"
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

#endif /* _PKT_SMB_HEADER_INCLUDED_ */
