/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <stdio.h>
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <p_ipv4.h>
#include <p_tcp.h>
#include <pkt/smb.h>
#include <p_smb.h>

#include <ctype.h>

#if 1
#define dbg(flow, fmt, x...) \
		do { \
			const struct smb_flow *__FLOW = flow; \
			if ( __FLOW->file ) { \
				fprintf(__FLOW->file, fmt , ##x); \
				fflush(__FLOW->file); \
			} \
		}while(0);
static void hex_dumpf(FILE *f, const uint8_t *tmp, size_t len, size_t llen)
{
	size_t i, j;
	size_t line;

	if ( NULL == f || 0 == len )
		return;

	for(j = 0; j < len; j += line, tmp += line) {
		if ( j + llen > len ) {
			line = len - j;
		}else{
			line = llen;
		}

		fprintf(f, " | %05x : ", j);

		for(i = 0; i < line; i++) {
			if ( isprint(tmp[i]) ) {
				fprintf(f, "%c", tmp[i]);
			}else{
				fprintf(f, ".");
			}
		}

		for(; i < llen; i++)
			fprintf(f, " ");

		for(i = 0; i < line; i++)
			fprintf(f, " %02x", tmp[i]);

		fprintf(f, "\n");
	}
	fprintf(f, "\n");
}
#define dbg_fopen fopen
#define dbg_fclose fclose
#else
#define dbg(x...) do { } while(0);
#define dbg_fopen(f, p) NULL;
#define dbg_fclose(f) do { } while(0);
static void hex_dumpf(FILE *f, const uint8_t *tmp, size_t len, size_t llen) {}
#endif

static struct _proto p_nbss = {
	.p_label = "nbss",
	.p_dcb_sz = sizeof(struct nbss_dcb),
};

static struct _proto p_smb = {
	.p_label = "smb",
	.p_dcb_sz = sizeof(struct smb_dcb),
};

static void reap_pending(struct smb_flow *f)
{
	unsigned int i, n;
	struct smb_pend *inp, *outp;

	dbg(f, "Transaction reaper called %u/%u:\n",
		f->num_trans_live, f->num_trans);
	for(inp = outp = f->pend, i = 0, n = f->num_trans, f->num_trans = 0;
			i < n; i++, inp++) {
		if ( !(inp->flags & SMB_PEND_CANCELLED) ) {
			*outp = *inp;
			outp++;
			f->num_trans++;
		}else{
			dbg(f, " Deleted transaction index %u\n",
				inp - f->pend);
		}
	}
}

static struct smb_pend *find_pending(struct smb_flow *f,
					const struct smb_dcb *dcb,
					int cancel)
{
	const struct smb_pkt *smb = dcb->smb;
	unsigned int i;

	for(i = 0; i < f->num_trans; i++) {
		if ( smb->smb_pid != f->pend[i].pid )
			continue;
		if ( !cancel && smb->smb_cmd != f->pend[i].cmd )
			continue;
		if ( smb->smb_mid != f->pend[i].mid )
			continue;
		return f->pend + i;
	}

	return NULL;
}

static void add_pending(struct smb_flow *f,
			const struct smb_dcb *dcb)
{
	const struct smb_pkt *smb = dcb->smb;

again:
	if ( f->num_trans >= SMB_MAX_PENDING ) {
		if ( f->num_trans > f->num_trans_live ) {
			reap_pending(f);
			goto again;
		}
		dbg(f, "MAX_PENDING exceeded %u/%u\n",
			f->num_trans_live, f->num_trans);
		/* FIXME: handle in similar way to response for non-pending
		 * transaction, are these cases isomorphic?
		 */
		return;
	}

	dbg(f, " Initiating new transaction %u\n", f->num_trans);
	f->pend[f->num_trans].flags = 0;
	f->pend[f->num_trans].cmd = smb->smb_cmd;
	f->pend[f->num_trans].mid = smb->smb_mid;
	f->pend[f->num_trans].pid = smb->smb_pid;
	f->num_trans++;
	f->num_trans_live++;
}

static void cancel_pending(struct smb_flow *f,
			struct smb_pend *pend)
{
	unsigned int idx;

	assert(pend >= f->pend && pend <= f->pend + (SMB_MAX_PENDING - 1));

	idx = pend - f->pend;
	dbg(f, " Cancelling transaction index %u\n", idx);

	f->pend[idx].flags |= SMB_PEND_CANCELLED;

	f->num_trans_live--;
}

static void delete_pending(struct smb_flow *f,
			struct smb_pend *pend)
{
	unsigned int idx, i;

	assert(pend >= f->pend && pend <= f->pend + (SMB_MAX_PENDING - 1));

	idx = pend - f->pend;
	dbg(f, " Closing transaction index %u\n", idx);

	assert((f->pend[idx].flags & SMB_PEND_CANCELLED) == 0);

	for(i = idx + 1; i < f->num_trans; i++)
		f->pend[i - 1] = f->pend[i];

	f->num_trans_live--;
	f->num_trans--;
}

static void state_update_generic(struct _pkt *pkt,
				 const struct tcpstream_dcb *tcp,
				 struct smb_dcb *dcb)
{
	struct smb_flow *f;

	f = tcp_sesh_get_flow(tcp->sesh);

	if ( dcb->flags & SMB_DCB_RESPONSE ) {
		struct smb_pend *pend;

		pend = find_pending(f, dcb, 0);
		if ( NULL == pend ) {
			dbg(f, " FUCKED: should not happen (yet)\n");
			return;
		}

		if ( pend->flags & SMB_PEND_CANCELLED ) {
			dbg(f, " Reply to CANCELLED transaction\n");
		}else{
			dbg(f, " Reply to pending transaction\n");
			delete_pending(f, pend);
		}
	}else{
		add_pending(f, dcb);
	}
}

static void smb_negproto(struct _pkt *pkt, 
			 const struct tcpstream_dcb *tcp,
			 struct smb_dcb *dcb)
{
	const uint8_t *buf, *end;
	const struct smb_flow *f;
	size_t sz;

	state_update_generic(pkt, tcp, dcb);

	if ( (dcb->flags & SMB_DCB_RESPONSE ) )
		return;

	f = tcp_sesh_get_flow(tcp->sesh);

	buf = dcb->payload;
	end = buf + dcb->payload_len;

	for(buf += 4; buf < end; buf += sz + 1) {
		buf += 1;
		sz = strnlen((char *)buf, (end - buf));
		dbg(f, " negproto: %.*s\n", sz, buf);
	}
}

static void smb_nt_cancel(struct _pkt *pkt,
			  const struct tcpstream_dcb *tcp,
			  struct smb_dcb *dcb)
{
	struct smb_flow *f;
	struct smb_pend *pend;

	f = tcp_sesh_get_flow(tcp->sesh);

	pend = find_pending(f, dcb, 1);
	if ( NULL == pend ) {
		dbg(f, " No transaction to cancel\n");
	}else{
		cancel_pending(f, pend);
	}
}

static int is_oplock_break(const struct tcpstream_dcb *tcp,
				  struct smb_dcb *dcb)
{
	const struct smb_locking_req *lck;

	if ( dcb->smb->smb_cmd != SMB_LOCKING_ANDX )
		return 0;
	if ( dcb->payload_len < sizeof(*lck) )
		return 0;

	lck = (struct smb_locking_req *)dcb->payload;
	if ( (lck->lock_type & SMB_LOCK_TYPE_BREAK) == 0 )
		return 0;

	return 1;
}

static void smb_lockingandx(struct _pkt *pkt,
			  const struct tcpstream_dcb *tcp,
			  struct smb_dcb *dcb)
{
	if ( is_oplock_break(tcp, dcb) ) {
		struct smb_flow *f;

		f = tcp_sesh_get_flow(tcp->sesh);
		if ( tcp->chan == TCP_CHAN_TO_CLIENT ) {
			f->num_oplock_break++;
			dbg(f, " OPLOCK_BREAK: %u now outstanding\n",
				f->num_oplock_break);
		}else{
			assert(f->num_oplock_break);
			f->num_oplock_break--;
			dbg(f, " ACK OPLOCK_BREAK: %u now outstanding\n",
				f->num_oplock_break);
		}
	}else{
		state_update_generic(pkt, tcp, dcb);
	}
}

struct smb_cmd {
	uint8_t id;
	const char *label;
	void (*state_update)(struct _pkt *pkt,
				const struct tcpstream_dcb *tcp,
				struct smb_dcb *dcb);
};

static const struct smb_cmd cmd_unknown = {
	.id = ~0,
	.label = "UNKNOWN",
	.state_update = state_update_generic,
};

static const struct smb_cmd cmds[] = {
	{.id = SMB_MKDIR,		.label = "mkdir"},
	{.id = SMB_RMDIR,		.label = "rmdir"},
	{.id = SMB_OPEN,		.label = "open"},
	{.id = SMB_CREATE,		.label = "create"},
	{.id = SMB_CLOSE,		.label = "Close"},
	{.id = SMB_FLUSH,		.label = "Flush"},
	{.id = SMB_DELETE,		.label = "Delete"},
	{.id = SMB_RENAME,		.label = "Rename"},
	{.id = SMB_GET_INFO,		.label = "QueryInfo"},
	{.id = SMB_SET_INFO,		.label = "SetInfo"},
	{.id = SMB_READ,		.label = "Read"},
	{.id = SMB_WRITE,		.label = "Write"},
	{.id = SMB_LOCK,		.label = "LockByteRange"},
	{.id = SMB_UNLOCK,		.label = "UnlockByteRange"},
	{.id = SMB_CREATE_TEMP,		.label = "CreateTemporary"},
	{.id = SMB_CREATE_NEW,		.label = "CreateNew"},
	{.id = SMB_CHECK_DIRECTORY,	.label = "CheckDirectory"},
	{.id = SMB_PROCESS_EXIT,	.label = "ProcessExit"},
	{.id = SMB_SEEK,		.label = "Seek"},
	{.id = SMB_LOCK_READ,		.label = "LockRead"},
	{.id = SMB_WRITE_UNLOCK,	.label = "WriteUnlock"},
	{.id = SMB_READ_RAW,		.label = "ReadRaw"},
	{.id = SMB_READ_BLOCK_MPX,	.label = "ReadBlockMultiplex"},
	{.id = SMB_READ_BLOCK_S,	.label = "ReadBlockSecondary"},
	{.id = SMB_WRITE_RAW,		.label = "WriteRaw"},
	{.id = SMB_WRITE_BLOCK_MPX,	.label = "WriteBlockMultiplex"},
	{.id = SMB_WRITE_BLOCK_S,	.label = "WriteBlockSecondary"},
	{.id = SMB_WRITE_COMPLETE,	.label = "WriteComplete"},
	{.id = SMB_SET_INFO2,		.label = "SetInfo2"},
	{.id = SMB_GET_INFO2,		.label = "QueryInfo2"},
	{.id = SMB_LOCKING_ANDX,	.label = "LockingAndX",
					.state_update = smb_lockingandx},
	{.id = SMB_TRANS,		.label = "Trans"},
	{.id = SMB_TRANS_S,		.label = "TransSecondary"},
	{.id = SMB_IOCTL,		.label = "Ioctl"},
	{.id = SMB_IOCTL_S,		.label = "IoctlSecondary"},
	{.id = SMB_COPY,		.label = "Copy"},
	{.id = SMB_MOVE,		.label = "Move"},
	{.id = SMB_ECHO,		.label = "Echo"},
	{.id = SMB_WRITE_CLOSE,		.label = "WriteClose"},
	{.id = SMB_OPEN_ANDX,		.label = "OpenAndX"},
	{.id = SMB_READ_ANDX,		.label = "ReadAndX"},
	{.id = SMB_WRITE_ANDX,		.label = "WriteAndX"},
	{.id = SMB_TRANS2,		.label = "Trans2"},
	{.id = SMB_TRANS2_S,		.label = "Trans2Secondary"},
	{.id = SMB_FIND_CLOSE2,		.label = "FindClose2"},
	{.id = SMB_FIND_NOTIFY_CLOSE,	.label = "FindNotifyClose"},
	/* 0x60 - 0x6e: unix/xenix */
	{.id = SMB_TREE_CONNECT,	.label = "TreeConnect"},
	{.id = SMB_TREE_DISCONNECT,	.label = "TreeDisconnect"},
	{.id = SMB_NEG_PROT,		.label = "NegotiateProtocol",
					.state_update = smb_negproto},
	{.id = SMB_SESSION_SETUP_ANDX,	.label = "SessionSetupAndX"},
	{.id = SMB_LOGOFF_ANDX,		.label = "LogoffAndX"},
	{.id = SMB_TREE_CONNECT_ANDX,	.label = "TreeConnectAndX"},
	{.id = SMB_GET_INFO_DISK,	.label = "QueryInfoDisk"},
	{.id = SMB_SEARCH,		.label = "Search"},
	{.id = SMB_FIND,		.label = "Find"},
	{.id = SMB_FIND_UNIQUE,		.label = "FindUnique"},
	{.id = SMB_FIND_CLOSE,		.label = "FindClose"},
	{.id = SMB_NT_TRANS,		.label = "NT_Trans"},
	{.id = SMB_NT_TRANS_S,		.label = "NT_TransSecondary"},
	{.id = SMB_NT_CREATE_ANDX,	.label = "NT_CreateAndX"},
	{.id = SMB_NT_CANCEL,		.label = "NT_CancelRequest",
					.state_update = smb_nt_cancel},
	{.id = SMB_NT_RENAME,		.label = "NT_Rename"},
	{.id = SMB_SPOOL_OPEN,		.label = "SpoolOpen"},
	{.id = SMB_SPOOL_LOCK,		.label = "SpoolLock"},
	{.id = SMB_SPOOL_CLOSE,		.label = "SpoolClose"},
	{.id = SMB_SPOOL_RETQ,		.label = "SpoolRetQ"},
	{.id = SMB_SENDS,		.label = "SendS"},
	{.id = SMB_SENDB,		.label = "SendB"},
	{.id = SMB_FWD_NAME,		.label = "ForwardName"},
	{.id = SMB_CANCEL_FWD,		.label = "CancelForward"},
	{.id = SMB_GETMAC,		.label = "GetMAC"},
	{.id = SMB_SEND_START,		.label = "SendStart"},
	{.id = SMB_SEND_TEXT,		.label = "SendText"},
	{.id = SMB_READ_BULK,		.label = "ReadBulk"},
	{.id = SMB_WRITE_BULK,		.label = "WriteBulk"},
	{.id = SMB_WRITE_BULK_DATA,	.label = "WriteBulkData"},
};

static const struct smb_cmd *find_cmd(uint8_t cmd)
{
	const struct smb_cmd *c = cmds;
	unsigned int n = sizeof(cmds)/sizeof(*cmds);

	while( n ) {
		unsigned int i;
		int ret;

		i = (n / 2);
		ret = cmd - c[i].id;
		if ( ret < 0 ) {
			n = i;
		}else if ( ret > 0 ) {
			c = c + (i + 1);
			n = n - (i + 1);
		}else{
			return &c[i];
		}
	}

	return &cmd_unknown;
}

static void dump_smb(const struct smb_flow *f, const struct smb_dcb *dcb)
{
	const struct smb_cmd *cmd;

	cmd = (dcb->cmd) ? dcb->cmd : find_cmd(dcb->smb->smb_cmd);
	dbg(f, "smb_pkt: %s : %s%s\n", cmd->label,
		(dcb->flags & SMB_DCB_DONT_TRACK) ? "STATELESS" : "",
		(dcb->flags & SMB_DCB_RESPONSE) ? "Response" : "Request");
	dbg(f, " PID/MID: %.4x / %.4x\n",
		sys_be16(dcb->smb->smb_pid), sys_be16(dcb->smb->smb_mid));
	dbg(f, " TID/UID: %.4x / %.4x\n",
		sys_be16(dcb->smb->smb_tid), sys_be16(dcb->smb->smb_uid));
	
}

static void smb_state_update(tcp_sesh_t sesh, tcp_chan_t chan, pkt_t pkt)
{
	const struct tcpstream_dcb *tcp;
	const struct smb_pkt *smb;
	struct smb_dcb *dcb;
	struct smb_flow *f;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = (struct smb_dcb *)tcp->dcb.dcb_next;
	f = tcp_sesh_get_flow(tcp->sesh);
	smb = dcb->smb;

	dcb->cmd = find_cmd(dcb->smb->smb_cmd);
	dump_smb(f, dcb);
	if ( dcb->flags & SMB_DCB_DONT_TRACK ) {
		dbg(f, "\n");
		return;
	}

	if ( dcb->cmd->state_update )
		dcb->cmd->state_update(pkt, tcp, dcb);
	else
		state_update_generic(pkt, tcp, dcb);

	dbg(f, "\n");
}

static void nbss_state_update(tcp_sesh_t sesh, tcp_chan_t chan, pkt_t pkt)
{
	const struct tcpstream_dcb *tcp;
	const struct nbss_dcb *dcb;
	const struct nbss_pkt *nb;
	const struct smb_flow *f;
	size_t plen;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = (struct nbss_dcb *)tcp->dcb.dcb_next;
	f = tcp_sesh_get_flow(tcp->sesh);
	nb = dcb->nb;
	plen = sys_be16(nb->nb_len);

	switch(nb->nb_type) {
		break;
	case NBSS_SESSION_SETUP:
		dbg(f, "mbss: session setup %s -> %s\n",
			dcb->called, dcb->caller);
		break;
	case NBSS_SESSION_SETUP_OK:
		dbg(f, "nbss: session setup OK\n");
		break;
	case NBSS_SESSION_SETUP_ERR:
		if ( plen ) {
			dbg(f, "nbss: session setup FUCKED: ");
			switch(nb->nb_u[0].err.code) {
			case NBSS_ERR_CALLED_NAME:
				dbg(f, "called name\n");
				break;
			case NBSS_ERR_CALLING_NAME:
				dbg(f, "calling name\n");
				break;
			case NBSS_ERR_NAME_NOT_PRESENT:
				dbg(f, "name not present\n");
				break;
			case NBSS_ERR_RESOURCE:
				dbg(f, "resource allocation failure\n");
				break;
			case NBSS_ERR_UNSPECIFIED:
				dbg(f, "unspecified\n");
				break;
			default:
				dbg(f, "code 0x%.2x\n",
					nb->nb_u[0].err.code);
			}
		}else{
			dbg(f, "nbss: session setup FUCKED\n");
		}
		break;
	case NBSS_SESSION_RETARGET:
		if ( plen >= sizeof(nb->nb_u[0].retarget) ) {
			ipstr_t ip;
			iptostr(ip, nb->nb_u[0].retarget.ip);
			dbg(f, "nbss: session setup RETARGET: %s:%u\n",
				ip, sys_be16(nb->nb_u[0].retarget.port));
		}else{
			dbg(f, "nbss: session setup RETARGET\n");
		}
		/* len = 6, (ip, port) */
		break;
	case NBSS_SESSION_KEEPALIVE:
		dbg(f, "nbss: session keepalive\n");
		break;
	default:
		dbg(f, "nbss: unknown packet type: 0x%.2x\n",
			nb->nb_type);
	}
}

static void state_update(tcp_sesh_t sesh, tcp_chan_t chan, pkt_t pkt)
{
	const struct tcpstream_dcb *tcp;
	struct _dcb *dcb;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = tcp->dcb.dcb_next;

	assert(dcb->dcb_proto == &p_nbss || dcb->dcb_proto == &p_smb);

	if ( dcb->dcb_proto == &p_nbss ) {
		nbss_state_update(sesh, chan, pkt);
	}else{
		smb_state_update(sesh, chan, pkt);
	}
}

static int check_oplock_break(const struct tcpstream_dcb *tcp,
					struct smb_dcb *dcb)
{
	struct smb_flow *f;

	f = tcp_sesh_get_flow(tcp->sesh);
	if ( tcp->chan & TCP_CHAN_TO_CLIENT ) {
		return 0;
	}else if ( f->num_oplock_break ) {
		return 0;
	}

	return 1;
}

static int check_regular_msgtype(const struct tcpstream_dcb *tcp,
					struct smb_dcb *dcb)
{
	struct smb_flow *f;

	f = tcp_sesh_get_flow(tcp->sesh);

	if ( dcb->smb->smb_flags & SMB_FLAGS_RESPONSE ) {
		if ( tcp->chan == TCP_CHAN_TO_SERVER ) {
			dcb->flags |= SMB_DCB_DONT_TRACK;
			return 0;
		}
		dcb->flags |= SMB_DCB_RESPONSE;
	}else{
		if ( tcp->chan == TCP_CHAN_TO_CLIENT ) {
			dcb->flags |= SMB_DCB_DONT_TRACK;
			return 0;
		}
		return 0;
	}

	dcb->pend = find_pending(f, dcb, 0);
	if ( dcb->pend )
		return 0;

	return 1;
}

static int is_non_pending_response(const struct tcpstream_dcb *tcp,
					struct smb_dcb *dcb)
{
	if ( is_oplock_break(tcp, dcb) ) {
		return check_oplock_break(tcp, dcb);
	}else{
		return check_regular_msgtype(tcp, dcb);
	}
}

static void smb_decode(struct _pkt *pkt)
{
	const struct tcpstream_dcb *tcp;
	const struct smb_flow *f;
	const struct smb_pkt *smb;
	struct smb_dcb *dcb;
	const uint8_t *buf;
	uint32_t hlen;
	size_t len;

	tcp = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = tcp_sesh_get_flow(tcp->sesh);

	assert(pkt->pkt_len >= sizeof(hlen));

	buf = pkt->pkt_base;
	len = pkt->pkt_len;

	hlen = sys_be32(*(uint32_t *)buf);
	hlen &= 0xffffff;
	buf += sizeof(hlen);
	len -= sizeof(hlen);

	smb = (struct smb_pkt *)(pkt->pkt_base + sizeof(hlen));
	assert(len >= hlen);

	assert(sizeof(smb->smb_magic) == strlen(SMB_MAGIC));
	if ( memcmp(smb->smb_magic, SMB_MAGIC, sizeof(smb->smb_magic)) ) {
		mesg(M_ERR, "smb: malformed packet");
		dbg(f, "malformed packet\n");
		hex_dumpf(f->file, buf, len, 16);
		/* FIXME */
		return;
	}

	buf += sizeof(*smb);
	len -= sizeof(*smb);

	dcb = (struct smb_dcb *)decode_layer0(pkt, &p_smb);
	assert(NULL != dcb);

	dcb->smb = smb;
	dcb->payload = buf;
	dcb->payload_len = len;

	if ( f->decode_flags & SMB_DECODE_STATELESS ) {
		dcb->flags = SMB_DCB_DONT_TRACK;
	}else{
		if ( is_non_pending_response(tcp, dcb) ) {
			dbg(f, "EEK: response for non-pending transaction\n");
			dump_smb(f, dcb);
			pkt->pkt_len = 0;
			return;
		}
	}
}

static void name_decode(const uint8_t *in, char *out, size_t nchar)
{
	size_t i;

	for(i = 0; i < nchar; i++, out++, in += 2) {
		*out = ((in[0] - 'A') << 4) | (in[1] - 'A');
		if ( ' ' == *out )
			break;
	}

	*out = '\0';
}

static void nbss_decode(struct _pkt *pkt)
{
	const struct tcpstream_dcb *tcp;
	const struct smb_flow *f;
	const struct nbss_pkt *nb;
	struct nbss_dcb *dcb;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	f = tcp_sesh_get_flow(tcp->sesh);

	nb = (struct nbss_pkt *)pkt->pkt_base;
	if ( pkt->pkt_len < sizeof(*nb) ||
		pkt->pkt_len < sizeof(*nb) + sys_be16(nb->nb_len) ) {
		mesg(M_WARN, "nbss: truncated packet, should not happen!");
		pkt->pkt_len = 0;
		return;
	}

	if ( nb->nb_type == NBSS_SESSION_MSG ) {
		smb_decode(pkt);
		return;
	}

	dcb = (struct nbss_dcb *)decode_layer0(pkt, &p_nbss);
	if ( NULL == dcb ) {
		pkt->pkt_len = 0;
		return;
	}

	dcb->nb = nb;
	if ( nb->nb_type == NBSS_SESSION_SETUP && sys_be16(nb->nb_len) >= 68 ) {
		name_decode(nb->nb_u[0].setup.called + 1, dcb->called, 16);
		name_decode(nb->nb_u[0].setup.caller + 1, dcb->caller, 16);
	}
}

static size_t get_len(const struct ro_vec *vec, size_t numv, size_t bytes)
{
	uint32_t ret;
	size_t i, b;

	if ( bytes < 4 )
		return 0;
	if ( vec[0].v_len >= 4 )
		return sys_be32(*(uint32_t *)vec[0].v_ptr) + 4;

	/* Assume 4 bytes is minumum value for maximum buffer size */
	assert(numv >= 2);
	assert(vec[0].v_len + vec[1].v_len >= 4);

	ret = 0;
	for(i = b = 0; i < vec[0].v_len; i++, b++)
		ret = (ret << 8) | vec[0].v_ptr[i];
	for(i = 0; b < 4; i++, b++)
		ret = (ret << 8) | vec[1].v_ptr[i];

	return ret + 4;
}

static size_t smb_get_len(const struct ro_vec *vec, size_t numv, size_t bytes)
{
	return get_len(vec, numv, bytes) & 0x1ffff;
}

static size_t nbt_get_len(const struct ro_vec *vec, size_t numv, size_t bytes)
{
	return get_len(vec, numv, bytes) & 0xffff;
}

/*
 * Let us assume that requests enter reasm buffer before before the response in
 * all legit cases. If during decode we encounter a response to a message which
 * is not in the pending transaction queue then the request must be in the
 * other reasm buffer. Now, here's the rub, it isn't necessarily at the front
 * of the other buffer.
 *
 * Who gives a fuck? Just call tcp_sesh_inject() on it multiple times...
 *
 * there's a potential deadlock if the last pending transaction to fit in the
 * flow buffer is an oplock break... so we need to be careful to avoid this
 *
 * A note on cancellations. A response and a cancel can be in flight
 * simultaneously. In this case the cancel myst take priority. How the fuck
 * to ensure this/ IOW responses to cancelled messages must appear as
 * stateless messages...
 * 
 * re-ordering some of the messages would be handy to get us out of a tight
 * squeeze if pending transaction buffer is full, would require more complex
 * stuff in tcp_reasm and more probably-ugly hackage here...  this is the case
 * where "need to allocate new queue entry to free up an old one". Only in this
 * case do we need to batch multiple messages up. I am now thinking the logic
 * here is going to be so hairy that the extra complication this entails will
 * definitely not be worth it
 */
static int do_push(tcp_sesh_t sesh, tcp_chan_t chan, int nbt)
{
	const struct ro_vec *vec;
	size_t numv, bytes, b, inj;
	struct smb_flow *f;
	tcp_chan_t c, wchan;
	int retry;

	f = tcp_sesh_get_flow(sesh);
	assert(f);

	wchan = tcp_sesh_get_wait(sesh);
	chan &= wchan;

	f->decode_flags = 0;

	while(chan) {
		if ( wchan != (TCP_CHAN_TO_SERVER|TCP_CHAN_TO_CLIENT) ) {
			assert(chan & wchan); /* htf? */
			c = wchan;
		}else if ( 0 == f->num_trans && (chan & TCP_CHAN_TO_SERVER) ) {
			/* what about flip pend? */
			c = TCP_CHAN_TO_SERVER;
		}else if ( chan & TCP_CHAN_TO_CLIENT ) {
			c = TCP_CHAN_TO_CLIENT;
		}else{
			c = TCP_CHAN_TO_SERVER;
		}

		retry = 0;

retry:
		vec = tcp_sesh_get_buf(sesh, c, &numv, &bytes);
		if ( NULL == vec ) {
			if ( retry ) {
				tcp_sesh_wait(sesh, c);
				return 0;
			}else{
				break;
			}
		}

		if ( nbt )
			b = nbt_get_len(vec, numv, bytes);
		else
			b = smb_get_len(vec, numv, bytes);

		if ( 0 == b || b > bytes ) {
			if ( retry ) {
				dbg(f, "push: no data in other chan\n");
				tcp_sesh_wait(sesh, c);
				return 0;
			}else{
				dbg(f, "push: no more data left in buffer\n");
				chan &= ~c;
				continue;
			}
		}

retry_samechan:
		inj = tcp_sesh_inject(sesh, c, b);
		if ( 0 == inj ) {
			if ( !retry ) {
				c = (c == TCP_CHAN_TO_SERVER) ?
						TCP_CHAN_TO_CLIENT :
						TCP_CHAN_TO_SERVER;
				if ( c & chan ) {
					dbg(f, "push: retry other chan\n");
					retry = 1;
					goto retry;
				}else{
					dbg(f, "push: wait for other chan\n");
					tcp_sesh_wait(sesh, c);
					return 0;
				}
			}else if ( b < bytes ) {
				goto ballsdeep;
			}else{
				dbg(f, "push: retrying same chan stateless\n");
				f->decode_flags |= SMB_DECODE_STATELESS;
				goto retry_samechan;
			}
		}

	}

	tcp_sesh_wait(sesh, TCP_CHAN_TO_CLIENT|TCP_CHAN_TO_SERVER);
	return 0;

	/* special case for batching all packets in reasm buffer */
ballsdeep:
	dbg(f, "balls deep %u/%u non-pending\n", b, bytes);
	assert(0);
	return 0;
}

static int smb_push(tcp_sesh_t sesh, tcp_chan_t chan)
{
	return do_push(sesh, chan, 0);
}

static int nbt_push(tcp_sesh_t sesh, tcp_chan_t chan)
{
	return do_push(sesh, chan, 1);
}

static int shutdown(tcp_sesh_t sesh, tcp_chan_t chan)
{
	return 1;
}

static objcache_t flow_cache;

#include "tcpip.h"
static int init(tcp_sesh_t sesh)
{
	struct smb_flow *f;
	static unsigned int snum;
	char sip[16], cip[16];
	char fn[64];

	f = objcache_alloc(flow_cache);
	if ( NULL == f )
		return 0;

	snprintf(fn, sizeof(fn), "./smb/sess%u.txt", snum++);
	f->file = dbg_fopen(fn, "w");
	iptostr(sip, sesh->s_addr);
	iptostr(cip, sesh->c_addr);
	dbg(f, "%s:%u -> %s:%u\n",
		sip, sys_be16(sesh->s_port),
		cip, sys_be16(sesh->c_port));

	f->num_trans = 0;
	f->num_trans_live = 0;
	f->num_oplock_break = 0;
	tcp_sesh_set_flow(sesh, f);
	tcp_sesh_wait(sesh, TCP_CHAN_TO_SERVER);

	return 1;
}

static void fini(tcp_sesh_t sesh)
{
	struct smb_flow *f;
	f = tcp_sesh_get_flow(sesh);
	dbg_fclose(f->file);
	objcache_free2(flow_cache, f);
}

static int smb_flow_ctor(void)
{
	flow_cache = objcache_init(NULL, "smb_flows",
					sizeof(struct smb_flow));
	if ( NULL == flow_cache )
		return 0;

	return 1;
}

static void smb_flow_dtor(void)
{
	objcache_fini(flow_cache);
}

static struct _decoder smb_decoder = {
	.d_decode = smb_decode,
	.d_flow_ctor = smb_flow_ctor,
	.d_flow_dtor = smb_flow_dtor,
	.d_label = "smb",
};

static struct _decoder nbss_decoder = {
	.d_decode = nbss_decode,
	.d_label = "nbss",
};

static struct tcp_app smb_app = {
	.a_push = smb_push,
	.a_state_update = state_update,
	.a_shutdown = shutdown,
	.a_init = init,
	.a_fini = fini,
	.a_decode = &smb_decoder,
	.a_label = "smb",
};

static struct tcp_app nbt_app = {
	.a_push = nbt_push,
	.a_state_update = state_update,
	.a_shutdown = shutdown,
	.a_init = init,
	.a_fini = fini,
	.a_decode = &nbss_decoder,
	.a_label = "nbt",
};

static void __attribute__((constructor)) smb_ctor(void)
{
	decoder_add(&smb_decoder);
	proto_add(&smb_decoder, &p_smb);

	decoder_add(&nbss_decoder);
	proto_add(&nbss_decoder, &p_nbss);

	tcp_app_register(&smb_app);
	tcp_app_register_dport(&smb_app, 445);

	tcp_app_register(&nbt_app);
	tcp_app_register_dport(&nbt_app, 139);
}
