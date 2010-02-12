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

struct smb_cmd {
	uint8_t id;
	const char *label;
	void (*req)(struct _pkt *pkt, struct smb_dcb *dcb);
	void (*resp)(struct _pkt *pkt, struct smb_dcb *dcb);
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
	{.id = SMB_NEG_PROT,		.label = "NegotiateProtocol"},
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

static void smb_state_update(tcp_sesh_t sesh, tcp_chan_t chan, pkt_t pkt)
{
	const struct tcpstream_dcb *tcp;
	const struct smb_dcb *dcb;
	const struct smb_pkt *smb;
	const struct smb_cmd *cmd;
	const struct smb_flow *f;

	tcp = (struct tcpstream_dcb *)pkt->pkt_dcb;
	dcb = (struct smb_dcb *)tcp->dcb.dcb_next;
	f = tcp_sesh_get_flow(tcp->sesh);
	smb = dcb->smb;

	cmd = find_cmd(smb->smb_cmd);
	if ( NULL == cmd ) {
		mesg(M_WARN, "smb: unknown command 0x%.2x", smb->smb_cmd);
		return;
	}

	dbg(f, "smb_pkt: %s : %s\n", cmd->label,
		(smb->smb_flags & SMB_FLAGS_RESPONSE) ? "Response" : "Request");
	dbg(f, " TCP_CHAN_%s\n",
		(tcp->chan == TCP_CHAN_TO_CLIENT) ? "TO_CLIENT" : "TO_SERVER");
	dbg(f, " PID/MID: %.4x / %.4x\n",
		sys_be16(smb->smb_pid), sys_be16(smb->smb_mid));
	dbg(f, " TID/UID: %.4x / %.4x\n",
		sys_be16(smb->smb_tid), sys_be16(smb->smb_uid));
	
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

#if 0
static void negproto_req(struct _pkt *pkt, const struct smb_pkt *smb,
			const uint8_t *buf, size_t len)
{
	const struct tcpstream_dcb *tcp;
	const uint8_t *end = buf + len;
	const struct smb_flow *f;
	size_t sz;

	tcp = (const struct tcpstream_dcb *)pkt->pkt_dcb;
	f = tcp_sesh_get_flow(tcp->sesh);

	for(buf += 4; buf < end; buf += sz + 1) {
		buf += 1;
		sz = strnlen((char *)buf, (end - buf));
		dbg(f, " negproto: %.*s\n", sz, buf);
	}
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
#endif

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
	if ( len < hlen ) {
		mesg(M_WARN, "smb: truncated packet, should not happen!");
		pkt->pkt_len = 0;
		return;
	}

	assert(sizeof(smb->smb_magic) == strlen(SMB_MAGIC));
	if ( memcmp(smb->smb_magic, SMB_MAGIC, sizeof(smb->smb_magic)) ) {
		mesg(M_ERR, "smb: malformed packet");
		dbg(f, "malformed packet\n");
		hex_dumpf(f->file, buf, len, 16);
		/* FIXME */
		return;
	}

	buf += sizeof(*smb);
	len -= sizeof(smb);

	dcb = (struct smb_dcb *)decode_layer0(pkt, &p_smb);
	if ( NULL == dcb ) {
		pkt->pkt_len = 0;
		return;
	}

	dcb->smb = smb;
	dcb->payload = buf;
	dcb->len = len;

	/* If this message begins a new transaction, it's OK as long as
	 * there is available slot in flow tracker of course.
	 *
	 * if it's a response to a pending transaction that's also cool
	 *
	 * problem arises if it's a response to an unknown transaction.
	 * there could be one of two reasons for this.
	 * firstly - the request part could just be sat in the other reasm buf
	 * secondly - someone could be fucking with us...
	 *
	 * in first case want to return 0 here and look in other buffer for
	 * that request...
	 *
	 * in second case, that's last thing we want to do...
	 */
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
 * re-ordering some of the messages would be handy to get us out of a tight
 * squeeze if pending transaction buffer is full, would require more complex
 * stuff in tcp_reasm and more probably-ugly hackage here...  this is the case
 * where "need to allocate new queue entry to free up an old one". Only in this
 * case do we need to batch multiple messages up
 */
static int do_push(tcp_sesh_t sesh, tcp_chan_t chan, int nbt)
{
	const struct ro_vec *vec;
	const struct smb_flow *f;
	size_t numv, bytes, b;
	tcp_chan_t c;

	f = tcp_sesh_get_flow(sesh);
	assert(f);

	chan &= (TCP_CHAN_TO_SERVER|TCP_CHAN_TO_CLIENT);

	while(chan) {
		if ( 0 == f->num_trans && (chan & TCP_CHAN_TO_SERVER) ) {
			c = TCP_CHAN_TO_SERVER;
		}else if ( chan & TCP_CHAN_TO_CLIENT ) {
			c = TCP_CHAN_TO_CLIENT;
		}else{
			c = TCP_CHAN_TO_SERVER;
		}

		vec = tcp_sesh_get_buf(sesh, c, &numv, &bytes);
		if ( NULL == vec )
			return 0;

		if ( nbt )
			b = nbt_get_len(vec, numv, bytes);
		else
			b = smb_get_len(vec, numv, bytes);

		if ( b > bytes || 0 == b ) {
			chan &= ~c;
			continue;
		}

		tcp_sesh_inject(sesh, c, b);
	}

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
	tcp_sesh_set_flow(sesh, f);
	tcp_sesh_wait(sesh, TCP_CHAN_TO_SERVER|TCP_CHAN_TO_CLIENT);

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
