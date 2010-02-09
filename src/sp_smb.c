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
			struct smb_flow *__FLOW = flow; \
			if ( __FLOW->file ) { \
				fprintf(__FLOW->file, fmt , ##x); \
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


struct smb_cmd {
	uint8_t id;
	const char *label;
	void (*req)(struct _pkt *pkt, const struct smb_pkt *smb,
			const uint8_t *buf, size_t len);
	void (*resp)(struct _pkt *pkt, const struct smb_pkt *smb,
			const uint8_t *buf, size_t len);
};

static void negproto_req(struct _pkt *pkt, const struct smb_pkt *smb,
			const uint8_t *buf, size_t len)
{
	const struct tcpstream_dcb *dcb;
	struct smb_flow *f;
	const uint8_t *end = buf + len;
	size_t sz;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	for(buf += 4; buf < end; buf += sz + 1) {
		buf += 1;
		sz = strnlen((char *)buf, (end - buf));
		dbg(f, " negproto: %.*s\n", sz, buf);
	}
}

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
	{.id = SMB_LOCKING_ANDX,	.label = "LockingAndX"},
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
					.req = negproto_req},
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
	{.id = SMB_NT_CANCEL,		.label = "NT_CancelRequest"},
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

	return NULL;
}

static int is_oplock_break(const struct smb_pkt *smb,
			const uint8_t *buf, size_t len)
{
	const struct smb_locking_req *lck = (const struct smb_locking_req *)buf;
	if ( smb->smb_cmd != 0x24 )
		return 0;
	if ( smb->smb_flags & SMB_FLAGS_RESPONSE )
		return 0;
	if ( len < sizeof(*lck) )
		return 0;
	return (0 != (lck->lock_type & SMB_LOCK_TYPE_BREAK));
}

static void cancel_transaction(struct smb_flow *f, const struct smb_pkt *smb)
{
	unsigned int i;

	for(i = 0; i <= f->cur_trans; i++) {
		struct smb_trans trans;
		uint8_t j;
		if ( f->trans[i].pid != smb->smb_pid )
			continue;
		if ( f->trans[i].mid != smb->smb_mid )
			continue;
		dbg(f, "smb: 0x%.2x transaction cancelled\n", f->trans[i].cmd);
		trans = f->trans[i];
		for(j = i + 1; j <= f->cur_trans; j++)
			f->trans[j - 1] = f->trans[j];
		f->trans[f->cur_trans] = trans;
		return;
	}
	dbg(f, "smb: unknown transaction cancelled\n");
}

static int unexpected_response(struct smb_flow *f, const struct smb_pkt *smb)
{
	unsigned int i;

	for(i = 0; i <= f->cur_trans; i++) {
		struct smb_trans trans;
		uint8_t j;
		if ( f->trans[i].cmd != smb->smb_cmd )
			continue;
		if ( f->trans[i].pid != smb->smb_pid )
			continue;
		if ( f->trans[i].mid != smb->smb_mid )
			continue;
		dbg(f, "smb: nested transaction completed\n");
		trans = f->trans[i];
		for(j = i + 1; j <= f->cur_trans; j++)
			f->trans[j - 1] = f->trans[j];
		f->cur_trans--;
		return 1;
	}

	f->cur_trans++;
	assert(f->cur_trans < SMB_NUM_TRANS);
	f->trans[f->cur_trans].flags = 0;
	dbg(f, "smb: nested transaction (level %u)\n", f->cur_trans + 1);
	return 0;
}

/* FIXME; this is fucked... should let multiple requests through because
 * some can be in flight for a long time... (shows in smbtorture)
 *
 * requires an sd_buffer_cleared() callback otherwise one bogus server
 * response could terminate reasm state machine...
 */
static int state_update(struct smb_flow *f, schan_t chan,
			const struct smb_pkt *smb,
			const uint8_t *buf, size_t len)
{
	struct smb_trans *tx;

	tx = &f->trans[f->cur_trans];

	switch( tx->flags & (SMB_TRANS_REQ|SMB_TRANS_OPLOCK_BREAK) ) {
	case SMB_TRANS_REQ|SMB_TRANS_OPLOCK_BREAK:
		dbg(f, "smb: completed transaction through oplock break\n");
	case SMB_TRANS_REQ:
		if ( chan == TCP_CHAN_TO_SERVER )
			return 0;
		if ( is_oplock_break(smb, buf, len) ) {
			f->cur_trans++;
			tx = &f->trans[f->cur_trans];
			tx->flags = SMB_TRANS_OPLOCK_BREAK;
			dbg(f, "smb: oplock break initiated\n");
			return 1;
		}
		if ( 0 == (smb->smb_flags & SMB_FLAGS_RESPONSE) )
			return 0;
		if ( tx->cmd != smb->smb_cmd ||
				tx->pid != smb->smb_pid ||
				tx->mid != smb->smb_mid ) {
			return unexpected_response(f, smb);
		}
		tx->flags &= ~SMB_TRANS_REQ;
		return 1;
	case SMB_TRANS_OPLOCK_BREAK:
		if ( chan == TCP_CHAN_TO_SERVER &&
				is_oplock_break(smb, buf, len) ) {
			dbg(f, "smb: oplock break resolved\n");
			f->cur_trans--;
			return 1;
		}
		dbg(f, "smb: nested transaction in oplock break\n");
		/* fall through */
	case 0:
		if ( chan == TCP_CHAN_TO_CLIENT )
			return 0;
		if ( (smb->smb_flags & SMB_FLAGS_RESPONSE) )
			return 0;
		if ( smb->smb_cmd == 0xa4 ) {
			cancel_transaction(f, smb);
			return 1;
		}
		tx->cmd = smb->smb_cmd;
		tx->pid = smb->smb_pid;
		tx->mid = smb->smb_mid;
		tx->flags |= SMB_TRANS_REQ;
		return 1;
	}

	return 0;
}

static void stream_clear(const struct _dcb *dcb)
{
	const struct tcpstream_dcb *stream;
	struct smb_flow *f;

	stream = (const struct tcpstream_dcb *)dcb;
	f = stream->s->flow;

	dbg(f, "smb: %s stream_clear\n",
		(stream->chan) ? "client" : "server");
}

static int smb_pkt(struct _pkt *pkt, const uint8_t *buf, size_t len)
{
	const struct tcpstream_dcb *dcb;
	struct smb_flow *f;
	const struct smb_pkt *smb;
	const struct smb_cmd *cmd;

	smb = (const struct smb_pkt *)buf;
	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	if ( len < sizeof(*smb) ||
		memcmp(smb->smb_magic, "\xffSMB", 4) ) {
		mesg(M_ERR, "smb: malformed packet");
		dbg(f, "malformed packet\n");
		hex_dumpf(f->file, buf, len, 16);
		return 1;
	}

	buf += sizeof(*smb);
	len -= sizeof(*smb);

	if ( !state_update(f, dcb->chan, smb, buf, len) )
		return 0;

	cmd = find_cmd(smb->smb_cmd);
	if ( NULL == cmd ) {
		mesg(M_WARN, "smb: unknown command 0x%.2x", smb->smb_cmd);
		return 1;
	}

	dbg(f, "smb_pkt: %s : %s\n", cmd->label,
		(smb->smb_flags & SMB_FLAGS_RESPONSE) ? "Response" : "Request");
	dbg(f, " TCP_CHAN_%s\n",
		(dcb->chan == TCP_CHAN_TO_CLIENT) ? "TO_CLIENT" : "TO_SERVER");
	dbg(f, " PID/MID: %.4x / %.4x\n",
		sys_be16(smb->smb_pid), sys_be16(smb->smb_mid));
	dbg(f, " TID/UID: %.4x / %.4x\n",
		sys_be16(smb->smb_tid), sys_be16(smb->smb_uid));

	if ( (smb->smb_flags & SMB_FLAGS_RESPONSE) ) {
		if ( cmd->resp )
			cmd->resp(pkt, smb, buf, len);
	}else{
		if ( cmd->req )
			cmd->req(pkt, smb, buf, len);
	}
	//hex_dumpf(f->file, buf, len, 16);
	dbg(f, "\n");

	return 1;
}

static ssize_t smb_get_len(struct ro_vec *vec, size_t numv, size_t bytes)
{
	uint8_t b1 = 0, b2 = 0, b3;
	size_t i, b;

	if ( bytes < 4 )
		return 0;

	for(i = b = 0; i < numv; b += vec[i].v_len, i++) {
		if ( b + vec[i].v_len > 1 && 1 >= b )
			b1 = vec[i].v_ptr[1 - b];
		if ( b + vec[i].v_len > 2 && 2 >= b )
			b2 = vec[i].v_ptr[2 - b];
		if ( b + vec[i].v_len > 3 ) {
			uint32_t len;
			b3 = vec[i].v_ptr[3 - b];
			len = (b1 << 16) | (b2 << 8) | b3;
			len += 4;

			if ( len > bytes )
				return 0;

			return len;
		}
	}

	return 0;
}

static ssize_t smb_push(struct _pkt *pkt, struct ro_vec *vec, size_t numv,
			size_t bytes)
{
	const struct tcpstream_dcb *dcb;
	struct smb_flow *f;
	const uint8_t *buf;
	ssize_t ret;
	size_t sz;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	ret = smb_get_len(vec, numv, bytes);
	if ( ret <= 0 )
		return ret;
	sz = (size_t)ret;
	
	if ( sz > vec[0].v_len ) {
		buf = dcb->reasm(dcb->sbuf, sz);
	}else{
		buf = vec[0].v_ptr;
	}

	if ( !smb_pkt(pkt, buf + 4, sz - 4) )
		ret = 0;

	return ret;
}

static void name_decode(const uint8_t *in, uint8_t *out, size_t nchar)
{
	size_t i;

	for(i = 0; i < nchar; i++, out++, in += 2) {
		*out = ((in[0] - 'A') << 4) | (in[1] - 'A');
		if ( ' ' == *out )
			break;
	}

	*out = '\0';
}

static int nbss_setup(struct _pkt *pkt, const struct nbss_pkt *nb, size_t len)
{
	uint8_t called[17], caller[17];
	const struct tcpstream_dcb *dcb;
	struct smb_flow *f;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	if ( len < 68 || dcb->chan != TCP_CHAN_TO_SERVER ) {
		mesg(M_ERR, "nbss: setup: invalid packet");
		return 1;
	}

	name_decode(nb->nb_u[0].setup.called + 1, called, 16);
	name_decode(nb->nb_u[0].setup.caller + 1, caller, 16);

	dbg(f, "mbss: session setup %s -> %s\n", called, caller);
	return 1;
}

static int nbss_pkt(struct _pkt *pkt,
			const struct nbss_pkt *nb,
			const uint8_t *buf, size_t len)
{
	const struct tcpstream_dcb *dcb;
	struct smb_flow *f;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	switch(nb->nb_type) {
	case NBSS_SESSION_MSG:
		return smb_pkt(pkt, buf, len);
	case NBSS_SESSION_SETUP:
		return nbss_setup(pkt, nb, len);
	case NBSS_SESSION_SETUP_OK:
		dbg(f, "nbss: session setup OK\n");
		break;
	case NBSS_SESSION_SETUP_ERR:
		dbg(f, "nbss: session setup FUCKED\n");
		/* len = 1, error code */
		break;
	case NBSS_SESSION_RETARGET:
		dbg(f, "nbss: session setup RETARGET\n");
		/* len = 6, (ip, port) */
		break;
	case NBSS_SESSION_KEEPALIVE:
		dbg(f, "nbss: session keepalive\n");
		break;
	default:
		dbg(f, "nbss: unknown packet type: 0x%.2x\n", nb->nb_type);
	}
	return 1;
}

static ssize_t nbt_get_len(struct ro_vec *vec, size_t numv, size_t bytes)
{
	uint8_t b1 = 0, b2 = 0, b3;
	size_t i, b;

	if ( bytes < 4 )
		return 0;

	for(i = b = 0; i < numv; b += vec[i].v_len, i++) {
		if ( b + vec[i].v_len > 1 && 1 >= b )
			b1 = vec[i].v_ptr[1 - b];
		if ( b + vec[i].v_len > 2 && 2 >= b )
			b2 = vec[i].v_ptr[2 - b];
		if ( b + vec[i].v_len > 3 ) {
			uint32_t len;
			b3 = vec[i].v_ptr[3 - b];
			len = (b2 << 8) | b3;
			if ( b1 & 1 )
				len |= (1 << 16);
			len += 4;
			if ( len > bytes )
				return 0;

			return len;
		}
	}

	return 0;
}

static ssize_t nbt_push(struct _pkt *pkt, struct ro_vec *vec, size_t numv,
			size_t bytes)
{
	const struct tcpstream_dcb *dcb;
	const struct nbss_pkt *nb;
	struct smb_flow *f;
	const uint8_t *buf;
	ssize_t ret;
	size_t sz;

	dcb = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = dcb->s->flow;

	ret = nbt_get_len(vec, numv, bytes);
	if ( ret <= 0 )
		return ret;
	sz = (size_t)ret;
	
	if ( sz > vec[0].v_len ) {
		buf = dcb->reasm(dcb->sbuf, sz);
	}else{
		buf = vec[0].v_ptr;
	}

	nb = (const struct nbss_pkt *)buf;
	if ( !nbss_pkt(pkt, nb, buf + sizeof(*nb), sz - sizeof(*nb)) )
		ret = 0;

	return ret;
}

static unsigned int snum;
static int flow_init(void *priv)
{
	struct tcp_session *s = priv;
	struct smb_flow *f = s->flow;
	char sip[16], cip[16];
	char fn[32];

	snprintf(fn, sizeof(fn), "./smb/sess%u.txt", snum++);
	f->file = dbg_fopen(fn, "w");
	iptostr(sip, s->s_addr);
	iptostr(cip, s->c_addr);
	dbg(f, "%s:%u -> %s:%u\n",
		sip, sys_be16(s->s_port),
		cip, sys_be16(s->c_port));

	f->cur_trans = 0;
	f->trans[f->cur_trans].flags = 0;
	return 1;
}

static void flow_fini(void *priv)
{
	struct tcp_session *s = priv;
	struct smb_flow *f = s->flow;
	dbg_fclose(f->file);
}

static struct _sdecode sd_nbt = {
	.sd_label = "nbt",
	.sd_push = nbt_push,
	.sd_stream_clear = stream_clear,
	.sd_flow_sz = sizeof(struct smb_flow),
	.sd_flow_init = flow_init,
	.sd_flow_fini = flow_fini,
	.sd_max_msg = (1 << 17),
};

static struct _sdecode sd_smb = {
	.sd_label = "smb",
	.sd_push = smb_push,
	.sd_stream_clear = stream_clear,
	.sd_flow_sz = sizeof(struct smb_flow),
	.sd_flow_init = flow_init,
	.sd_flow_fini = flow_fini,
	.sd_max_msg = (1 << 24),
};

static void __attribute__((constructor)) smb_ctor(void)
{
	sdecode_add(&sd_nbt);
	sdecode_register(&sd_nbt, SNS_TCP, sys_be16(139));
	sdecode_add(&sd_smb);
	sdecode_register(&sd_smb, SNS_TCP, sys_be16(445));
}
