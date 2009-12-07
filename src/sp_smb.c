/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <stdio.h>
#include <firestorm.h>
#include <f_decode.h>
#include <f_stream.h>
#include <p_ipv4.h>
#include <pkt/tcp.h>
#include <pkt/smb.h>
#include "tcpip.h"

#include <limits.h>
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
#else
#define dbg(x...) do { } while(0);
static void hex_dumpf(FILE *f, const uint8_t *tmp, size_t len, size_t llen) {}
#endif


struct smb_cmd {
	uint8_t id;
	const char *label;
	void (*req)(struct _stream *ss, const struct smb_pkt *smb,
			const uint8_t *buf, size_t len);
	void (*resp)(struct _stream *ss, const struct smb_pkt *smb,
			const uint8_t *buf, size_t len);
};

static void negproto_req(struct _stream *ss, const struct smb_pkt *smb,
			const uint8_t *buf, size_t len)
{
	struct smb_flow *f = ss->s_flow;
	const uint8_t *end = buf + len;
	size_t sz;

	buf += 4;

	while( buf < end ) {
		buf += 1;
		sz = strnlen((char *)buf, (end - buf));
		dbg(f, " negproto: %.*s\n", sz, buf);
		buf += sz + 1;
	}
}

static const struct smb_cmd cmds[] = {
	{.id = 0x04, .label = "Close"},
	{.id = 0x10, .label = "CheckDirectory"},
	{.id = 0x24, .label = "LockingAndX"},
	{.id = 0x25, .label = "Trans"},
	{.id = 0x2b, .label = "Echo"},
	{.id = 0x2e, .label = "ReadAndX"},
	{.id = 0x2f, .label = "WriteAndX"},
	{.id = 0x32, .label = "Trans2"},
	{.id = 0x71, .label = "TreeDisconnect"},
	{.id = 0x72, .label = "NegotiateProtocol",
			.req = negproto_req},
	{.id = 0x73, .label = "SessionSetupAndX"},
	{.id = 0x74, .label = "LogoffAndX"},
	{.id = 0x75, .label = "TreeConnectAndX"},
	{.id = 0xa0, .label = "NT_Trans"},
	{.id = 0xa2, .label = "NT_CreateAndX"},
	{.id = 0xa4, .label = "NT_CancelRequest"},
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
	uint8_t i;

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
	uint8_t i;

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

static int state_update(struct smb_flow *f, unsigned int chan,
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

static int smb_pkt(struct _stream *ss, struct smb_flow *f, unsigned int chan,
			const uint8_t *buf, size_t len)
{
	const struct smb_pkt *smb;
	const struct smb_cmd *cmd;

	smb = (const struct smb_pkt *)buf;

	if ( len < sizeof(*smb) ||
		memcmp(smb->smb_magic, "\xffSMB", 4) ) {
		mesg(M_ERR, "smb: bad packet");
		return 1;
	}

	buf += sizeof(*smb);
	len -= sizeof(*smb);

	if ( !state_update(f, chan, smb, buf, len) )
		return 0;

	cmd = find_cmd(smb->smb_cmd);
	if ( NULL == cmd ) {
		mesg(M_WARN, "smb: unknown command 0x%2x", smb->smb_cmd);
		return 1;
	}

	dbg(f, "smb_pkt: %s : %s\n", cmd->label,
		(smb->smb_flags & SMB_FLAGS_RESPONSE) ? "Response" : "Request");
	dbg(f, " TCP_CHAN_%s\n",
		(chan == TCP_CHAN_TO_CLIENT) ? "TO_CLIENT" : "TO_SERVER");
	dbg(f, " PID/MID: %.4x / %.4x\n",
		sys_be16(smb->smb_pid), sys_be16(smb->smb_mid));
	dbg(f, " TID/UID: %.4x / %.4x\n",
		sys_be16(smb->smb_tid), sys_be16(smb->smb_uid));

	if ( (smb->smb_flags & SMB_FLAGS_RESPONSE) ) {
		if ( cmd->resp )
			cmd->resp(ss, smb, buf, len);
	}else{
		if ( cmd->req )
			cmd->req(ss, smb, buf, len);
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

static ssize_t smb_push(struct _stream *s, unsigned int chan,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	struct smb_flow *f;
	const uint8_t *buf;
	ssize_t ret;
	size_t sz;
	int do_free;

	f = s->s_flow;

	ret = smb_get_len(vec, numv, bytes);
	if ( ret <= 0 )
		return ret;
	sz = (size_t)ret;
	
	if ( sz > vec[0].v_len ) {
		buf = malloc(sz);
		s->s_reasm(s, (uint8_t *)buf, sz);
		do_free = 1;
	}else{
		buf = vec[0].v_ptr;
		do_free = 0;
	}

	if ( !smb_pkt(s, f, chan, buf + 4, sz - 4) )
		ret = 0;

	if ( do_free )
		free((void *)buf);

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

static int nbss_setup(struct _stream *s, struct smb_flow *f, unsigned int chan,
			const uint8_t *buf, size_t len)
{
	uint8_t called[17], caller[17];

	if ( len < 68 || chan != TCP_CHAN_TO_SERVER ) {
		mesg(M_ERR, "nbss: setup: invalid packet");
		return 1;
	}

	name_decode(buf + 1, called, 16);
	name_decode(buf + 35, caller, 16);

	dbg(f, "mbss: session setup %s -> %s\n", called, caller);
	return 1;
}

static int nbss_pkt(struct _stream *s, struct smb_flow *f, unsigned int chan,
			const struct nbss_pkt *nb,
			const uint8_t *buf, size_t len)
{
	switch(nb->nb_type) {
	case 0x00:
		return smb_pkt(s, f, chan, buf, len);
	case 0x81:
		return nbss_setup(s, f, chan, buf, len);
	case 0x82:
		dbg(f, "nbss: session setup OK\n");
		break;
	case 0x83:
		dbg(f, "nbss: session setup FUCKED\n");
		/* len = 1, error code:
		 * 	0x80: Not Listening On Called Name
		 *	0x81: Not Listening For Calling Name 
		 *	0x82: Called Name Not Present
		 *	0x83: insufficient resources
		 *	0x8f: unspecified error
		*/
		break;
	case 0x84:
		dbg(f, "nbss: session setup RETARGET\n");
		/* len = 6, (ip, port) */
		break;
	case 0x85:
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

static ssize_t nbt_push(struct _stream *s, unsigned int chan,
		struct ro_vec *vec, size_t numv, size_t bytes)
{
	const struct nbss_pkt *nb;
	struct smb_flow *f;
	const uint8_t *buf;
	ssize_t ret;
	size_t sz;
	int do_free;

	f = s->s_flow;

	ret = nbt_get_len(vec, numv, bytes);
	if ( ret <= 0 )
		return ret;
	sz = (size_t)ret;
	
	if ( sz > vec[0].v_len ) {
		buf = malloc(sz);
		s->s_reasm(s, (uint8_t *)buf, sz);
		do_free = 1;
	}else{
		buf = vec[0].v_ptr;
		do_free = 0;
	}

	nb = (const struct nbss_pkt *)buf;
	if ( !nbss_pkt(s, f, chan, nb, buf + sizeof(*nb), sz - sizeof(*nb)) )
		ret = 0;

	if ( do_free )
		free((void *)buf);

	return ret;
}

static unsigned int snum;
static int flow_init(struct _stream *ss)
{
	struct tcp_stream *s = (struct tcp_stream *)ss;
	struct smb_flow *f = s->stream.s_flow;
	char sip[16], cip[16];
	char fn[32];

	snprintf(fn, sizeof(fn), "./smb/sess%u.txt", snum++);
	f->file = fopen(fn, "w");
	iptostr(sip, s->s->s_addr);
	iptostr(cip, s->s->c_addr);
	dbg(f, "%s:%u -> %s:%u\n",
		sip, sys_be16(s->s->s_port),
		cip, sys_be16(s->s->c_port));

	f->cur_trans = 0;
	f->trans[f->cur_trans].flags = 0;
	return 1;
}

static void flow_fini(struct _stream *ss)
{
	struct tcp_stream *s = (struct tcp_stream *)ss;
	struct smb_flow *f = s->stream.s_flow;
	fclose(f->file);
}

struct _sproto sp_nbt = {
	.sp_label = "nbt",
	.sp_push = nbt_push,
	.sp_flow_sz = sizeof(struct smb_flow),
	.sp_flow_init = flow_init,
	.sp_flow_fini = flow_fini,
};

struct _sproto sp_smb = {
	.sp_label = "smb",
	.sp_push = smb_push,
	.sp_flow_sz = sizeof(struct smb_flow),
	.sp_flow_init = flow_init,
	.sp_flow_fini = flow_fini,
};

static void __attribute__((constructor)) smb_ctor(void)
{
	sproto_add(&sp_nbt);
	sproto_register(&sp_nbt, SNS_TCP, sys_be16(139));
	sproto_add(&sp_smb);
	sproto_register(&sp_smb, SNS_TCP, sys_be16(445));
}
