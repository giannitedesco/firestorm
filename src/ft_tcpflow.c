/*
 * This file is part of Firestorm NIDS
 * Copyright (c) Gianni Tedesco 2008
 * This program is released under the terms of the GNU GPL version 3
 *
 * TODO:
 *  o Put state data in to DCB
 *  o Handle ICMP errors
 *  o check for broadcasts if possible
*/
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_stream.h>
#include <p_tcp.h>
#include <pkt/ip.h>
#include <pkt/tcp.h>
#include <pkt/icmp.h>
#include <p_ipv4.h>

#include "tcpip.h"

#define STATE_DEBUG 0
#define SEGMENT_DEBUG 0
#define STREAM_DEBUG 0

#if STATE_DEBUG
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do{}while(0)
#define dhex_dump(x...) do{}while(0)
#endif

#if SEGMENT_DEBUG
#include <stdio.h>
#include <stdarg.h>
#endif

/* configuration options */
static const uint8_t minttl = 1;
static const uint8_t reassemble = 1;

/* flow hash */
#define TCPHASH 509 /* prime */
static struct tcp_session *hash[TCPHASH];

/* memory caches */
static mempool_t tcp_pool;
static objcache_t session_cache;
static objcache_t sstate_cache;
static objcache_t flow_cache;

/* timeout lists */
static LIST_HEAD(lru);
static LIST_HEAD(tmo_msl);

/* stats */
static unsigned int num_active;
static unsigned int max_active;
static unsigned int num_segments;
static unsigned int state_errs;

static unsigned int num_csum_errs;
static unsigned int num_ttl_errs;
static unsigned int num_timeouts;
static unsigned int num_oom;

struct tcpseg {
	timestamp_t ts;
	const struct pkt_iphdr *iph;
	const struct pkt_tcphdr *tcph;
	uint32_t ack, seq, win, seq_end;
	uint16_t hash, len;
	uint32_t tsval;
	unsigned int saw_tstamp;
	uint8_t *payload;
	struct tcp_state *snd, *rcv;
	unsigned int to_server;
};

static void dbg_segment(struct tcpseg *cur)
{
#if SEGMENT_DEBUG
	static const char tcpflags[] = "FSRPAUEC";
	uint8_t x, i;
	char ackbuf[16];
	char fstr[9];
	ipstr_t sip, dip;

	iptostr(sip, cur->iph->saddr);
	iptostr(dip, cur->iph->daddr);

	for(i = 0, x = 1; x; i++, x <<= 1)
		fstr[i] = (cur->tcph->flags & x) ? tcpflags[i] : '*';

	fstr[i] = '\0';

	if ( cur->tcph->flags & TCP_ACK ) {
		snprintf(ackbuf, sizeof(ackbuf), " a:%x", cur->ack);
	}else{
		ackbuf[0] = '\0';
	}

	mesg(M_DEBUG, "\033[36m[%s] %s:%u %s:%u s:%x%s w:%u l:%u\033[0m", fstr,
		sip, sys_be16(cur->tcph->sport),
		dip, sys_be16(cur->tcph->dport),
		cur->seq, ackbuf, cur->win, cur->len);
#endif
}

static void dbg_stream(const char *label, struct tcp_state *s)
{
#if STREAM_DEBUG
	if ( NULL == s )
		return;
	mesg(M_DEBUG, "\033[34m%s: una=%.8x nxt=%.8x "
			"wl1=%.8x wl2=%.8x wnd=%u\033[0m",
			label, s->snd_una, s->snd_nxt,
			s->snd_wl1, s->snd_wl2, s->snd_wnd);
#endif
}

/* Wrap-safe seq/ack calculations */
static int between(uint32_t s1, uint32_t s2, uint32_t s3)
{
	return s3 - s2 >= s1 - s2; /* is s2<=s1<=s3 ? */
}

static uint32_t tcp_receive_window(struct tcp_state *s)
{
	int32_t win = s->snd_wl2 + s->snd_wnd - s->snd_nxt;
	if ( win < 0 )
		win = 0;
	return (uint32_t)win;
}

static int tcp_sequence(struct tcp_state *s, uint32_t seq, uint32_t end_seq)
{
	return !tcp_before(end_seq, s->snd_wl2) &&
		!tcp_after(seq, s->snd_nxt + tcp_receive_window(s));
}

static void detach_protocol(struct tcp_session *s)
{
	if ( NULL == s->proto )
		return;
	if ( s->flow ) {
		s->proto->sd_flow_fini(s);
		objcache_free2(flow_cache, s->flow);
		s->flow = NULL;
	}
	s->proto = s->flow = NULL;
}

static void abort_reasm(struct tcp_session *s)
{
	_tcp_reasm_free(s, 1);
	detach_protocol(s);
	s->reasm = 0;
}

static void attach_protocol(struct tcp_session *s)
{
	if ( !reassemble )
		return;

	s->proto = sdecode_find(SNS_TCP, s->s_port);
	if ( NULL == s->proto )
		goto fuckit;

	if ( flow_cache )
		s->flow = _tcp_alloc(s, flow_cache, 0);

	if ( s->flow && !s->proto->sd_flow_init(s) )
		goto fuckit;

	return;

fuckit:
	abort_reasm(s);
}

static void reassemble_point(struct tcp_session *s,
				unsigned int chan,
				uint32_t ack)
{
	if ( !reassemble )
		return;
	if ( !s->proto )
		return;
	if ( !_tcp_stream_push(s, chan, ack) )
		abort_reasm(s);
}

static void reasm_data(struct tcpseg *cur, struct tcp_session *s)
{
	if ( !reassemble )
		return;
	if ( !s->reasm )
		return;
	if ( !_tcp_reasm_inject(s, cur->to_server, cur->seq,
				cur->len, cur->payload) )
		abort_reasm(s);
}

/* Hash function.
 * Hashes to the same value even when source and destinations are inverted.
 */
_constfn static uint16_t tcp_hashfn(uint32_t saddr, uint32_t daddr,
					uint16_t sport, uint16_t dport)
{
	uint32_t h;
	h = ((saddr ^ sport) ^ (daddr ^ dport));
	h ^= h >> 16;
	h ^= h >> 8;
	h %= TCPHASH;
	return h;
}

/* HASH: Unlink a session from the session hash */
static void tcp_hash_unlink(struct tcp_session *s)
{
	if (s->hash_next)
		s->hash_next->hash_pprev = s->hash_pprev;
	*s->hash_pprev = s->hash_next;
}

/* HASH: Link a session in to the TCP session hash */
static void tcp_hash_link(struct tcp_session *s, uint16_t bucket)
{
	if ((s->hash_next = hash[bucket]))
		s->hash_next->hash_pprev = &s->hash_next;
	hash[bucket] = s;
	s->hash_pprev = &hash[bucket];
}

/* HASH: Move to front of hash collision chain */
static void tcp_hash_mtf(struct tcp_session *s, uint16_t bucket)
{
	tcp_hash_unlink(s);
	tcp_hash_link(s, bucket);
}

/* Find a TCP session given a packet */
static struct tcp_session *tcp_collide(struct tcp_session *s,
					const struct pkt_iphdr *iph,
					const struct pkt_tcphdr *tcph,
					unsigned int *to_server)
{
	for (; s; s = s->hash_next) {
		if (	s->s_addr == iph->saddr &&
			s->c_addr == iph->daddr &&
			s->s_port == tcph->sport &&
			s->c_port == tcph->dport ) {
			*to_server = TCP_CHAN_TO_CLIENT;
			return s;
		}
		if (	s->c_addr == iph->saddr &&
			s->s_addr == iph->daddr &&
			s->c_port == tcph->sport &&
			s->s_port == tcph->dport ) {
			*to_server = TCP_CHAN_TO_SERVER;
			return s;
		}
	}

	return NULL;
}

/* Parse TCP options just for timestamps */
static int tcp_fast_options(struct tcpseg *cur)
{
	const struct pkt_tcphdr *t = cur->tcph;
	char *tmp, *end;
	size_t ofs = t->doff << 2;

	/* Return if we don't have any */
	if ( ofs <= sizeof(struct pkt_tcphdr))
		return 0;

	/* Work out where they begin and end */
	tmp = end = (char *)t;
	tmp += sizeof(struct pkt_tcphdr);
	end += ofs;

	while ( tmp < end ) {
		size_t step;

		/* XXX: We continue past an EOL. Is that right? */
		switch ( *tmp ) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			tmp++;
			continue;
		}

		if ( tmp+1 >= end )
			break;

		switch ( *tmp ) {
		case TCPOPT_TIMESTAMP:
			if ( tmp + 10 >= end )
				break;
			cur->tsval = sys_be32(*((uint32_t *)(tmp + 2)));
			return 1;
		}

		step = *(tmp + 1);
		if ( step < 2 ) {
			mesg(M_DEBUG, "Malformed tcp options");
			step = 2;
		}
		tmp += step;
	}

	return 0;
}

/* This will parse TCP options for SYN packets */
static void tcp_syn_options(struct tcp_state *s,
				const struct pkt_tcphdr *t,
				uint32_t sec)
{
	uint8_t *tmp, *end;
	size_t ofs = t->doff << 2;

	/* Return if we don't have any */
	if ( ofs <= sizeof(struct pkt_tcphdr))
		return;

	/* Work out where they begin and end */
	tmp = end = (uint8_t *)t;
	tmp += sizeof(struct pkt_tcphdr);
	end += ofs;

	while ( tmp < end ) {
		size_t step;

		/* XXX: We continue past an EOL. Is that right? */
		switch(*tmp) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			tmp++;
			continue;
		}

		if ( tmp + 1 >= end )
			break;

		/* Deal with fixed size options */
		switch ( *tmp ) {
		case TCPOPT_SACK_PERMITTED:
			s->flags |= TF_SACK_OK;
			break;
		case TCPOPT_TIMESTAMP:
			s->flags |= TF_TSTAMP_OK;

			/* Only check the bit we want */
			if ( tmp + 10 >= end )
				break;

			s->ts_recent = sys_be32(*((uint32_t *)(tmp + 2)));
			s->ts_recent_stamp = sec;

			break;
		case TCPOPT_WSCALE:
			if ( tmp + 2 >= end )
				break;

			s->flags |= TF_WSCALE_OK;

			/* rfc1323: must log error and limit to 14 */
			s->scale = *(tmp + 2);
			if ( s->scale > 14 )
				s->scale = 14;
			break;
		}

		step = *(tmp + 1);
		if ( step < 2 ) {
			mesg(M_WARN, "Malformed tcp options");
			step = 2;
		}

		tmp += step;
	}
}

static void tcp_free(struct tcp_session *s)
{
	tcp_hash_unlink(s);
	list_del(&s->tmo);
	list_del(&s->lru);

	if ( s->reasm ) {
		_tcp_reasm_free(s, 0);
		detach_protocol(s);
	}

	if ( s->s_wnd )
		objcache_free2(sstate_cache, s->s_wnd);

	objcache_free2(session_cache, s);
	num_active--;
}

/* TMO: Check timeouts */
static void tcp_tmo_check(struct list_head *list, timestamp_t now)
{
	struct tcp_session *s;

	/* Actually, the generic list API made this more ugly */
	while ( !list_empty(list) ) {
		s = list_entry(list->next, struct tcp_session, tmo);
		if ( !tcp_after(now / TIMESTAMP_HZ, s->expire) )
			return;

		tcp_free(s);
		num_timeouts++;
	}
}

/* TMO: Set expiry */
static void set_expire(struct list_head *list,
				struct tcp_session *s,
				timestamp_t t)
{
	s->expire = t / TIMESTAMP_HZ;
	list_move_tail(&s->tmo, list);
}

static void timer_msl(struct tcpseg *cur, struct tcp_session *s)
{
	set_expire(&tmo_msl, s, cur->ts + TCP_TMO_MSL);
}

static void set_lru(struct tcpseg *cur, struct tcp_session *s)
{
	list_move_tail(&s->lru, &lru);
}

static void init_wnd(struct tcpseg *cur, struct tcp_state *s)
{
	memset(s, 0, sizeof(*s));
	s->snd_una = cur->seq;
	s->snd_nxt = s->snd_una + 1;
	s->snd_wnd = cur->win;
	s->snd_wl1 = cur->seq;
	s->snd_wl2 = cur->ack;
	tcp_syn_options(s, cur->tcph, cur->ts / TIMESTAMP_HZ);
}

void *_tcp_alloc(struct tcp_session *s, objcache_t o, int reasm)
{
	struct tcp_session *ss, *tmp;
	void *ret;

again:
	ret = objcache_alloc(o);
	if ( ret )
		return ret;

	list_for_each_entry_safe(ss, tmp, &lru, lru) {
		if ( s == ss )
			continue;
		if ( reasm && !ss->reasm )
			continue;
		tcp_free(ss);
		num_oom++;
		goto again;
	}

	return NULL;
}

static struct tcp_session *new_session(struct tcpseg *cur)
{
	struct tcp_session *s;

	/* Track syn packets only for now. This could be re-jiggled for
	 * flow accounting:
	 *  - move this check after allocation
	 *  - for stray packets: don't transition + keep server/client zeroed
	 */
	if ( (cur->tcph->flags & (TCP_SYN|TCP_ACK|TCP_FIN|TCP_RST))
			!= TCP_SYN ) {
		dmesg(M_DEBUG, "not a valid syn packet");
		return NULL;
	}

	s = _tcp_alloc(NULL, session_cache, 0);
	if ( s == NULL ) {
		mesg(M_CRIT, "tcp OOM");
		return NULL;
	}

	INIT_LIST_HEAD(&s->tmo);
	INIT_LIST_HEAD(&s->lru);

	dmesg(M_DEBUG, "#1 - syn: half-state allocated");

	s->c_addr = cur->iph->saddr;
	s->s_addr = cur->iph->daddr;
	s->c_port = cur->tcph->sport;
	s->s_port = cur->tcph->dport;

	s->state = TCP_SESSION_S1;

	/* stats */
	num_active++;
	if ( num_active > max_active )
		max_active = num_active;

	/* Setup initial window tracking state machine */
	init_wnd(cur, &s->c_wnd);
	s->s_wnd = NULL;

	/* link it all up and set up timeouts*/
	tcp_hash_link(s, cur->hash);
	timer_msl(cur, s);

	INIT_LIST_HEAD(&s->lru);
	set_lru(cur, s);

	s->proto = NULL;
	s->flow = NULL;

	return s;
}

static void s1_processing(struct tcpseg *cur, struct tcp_session *s)
{
	assert(!cur->to_server);

	/* Authenticate packet by checking ACK */
	if ( cur->tcph->flags & TCP_ACK ) {
		if ( !(between(cur->ack,
				cur->rcv->snd_una, cur->rcv->snd_nxt)) ) {
			dmesg(M_DEBUG, "bad ack on syn+ack");
			state_errs++;
			return;
		}
	}else{
		dmesg(M_DEBUG, "missing ack on syn+ack");
		state_errs++;
		return;
	}

	/* Technically FIN is invalid here */
	if ( cur->tcph->flags & (TCP_FIN|TCP_RST) ) {
		dmesg(M_DEBUG, "connection refused");
		s->state = TCP_SESSION_C;
		return;
	}

	if ( cur->tcph->flags & TCP_SYN ) {
		cur->seq_end++;

		dmesg(M_DEBUG, "#2 - syn+ack");
		s->s_wnd = _tcp_alloc(s, sstate_cache, 0);
		assert(NULL != s->s_wnd);
		cur->snd = s->s_wnd;
		init_wnd(cur, s->s_wnd);

		if ( !(s->s_wnd->flags & TF_WSCALE_OK) ||
			!(s->c_wnd.flags & TF_WSCALE_OK) ) {
			s->s_wnd->scale = 0;
			s->c_wnd.scale = 0;
		}else{
			dmesg(M_DEBUG, "wscale in use c=%u s=%u",
				s->c_wnd.scale, s->s_wnd->scale);
		}

		s->s_wnd->snd_wnd = cur->win;
		s->s_wnd->snd_wl1 = cur->seq;
		s->s_wnd->snd_wl2 = cur->ack;

		s->state = TCP_SESSION_S2;
		list_del(&s->tmo);
	}
}

static int sequence_check(struct tcpseg *cur, struct tcp_session *s)
{
	if ( s->state == TCP_SESSION_S2 )
		return (cur->seq == cur->snd->snd_nxt);
	return tcp_sequence(cur->rcv, cur->seq, cur->seq_end);
}

static int ack_processing(struct tcpseg *cur, struct tcp_session *s)
{
	assert(cur->tcph->flags & TCP_ACK);

	if ( s->state == TCP_SESSION_S2 ) {
		if ( !cur->to_server ) {
			dmesg(M_DEBUG, "syn+ack resend?");
			state_errs++;
			return 0;
		}

		/* If SND.UNA =< SEG.ACK =< SND.NXT  */
		if ( !tcp_after(s->s_wnd->snd_una, cur->ack) &&
			!tcp_after(cur->ack, s->s_wnd->snd_nxt) ) {
			dmesg(M_DEBUG, "#3 - ack");
			s->c_wnd.snd_wnd = cur->win;
			s->c_wnd.snd_wl1 = cur->seq;
			s->c_wnd.snd_wl2 = cur->ack;
			if ( _tcp_reasm_init(s) )
				s->reasm = 1;
			s->state = TCP_SESSION_S3;
		}else{
			dmesg(M_DEBUG, "bad ACK on 3whs");
			state_errs++;
		}

		return 1;
	}

	/* If SND.UNA < SEG.ACK =< SND.NXT then */
	if ( tcp_before(cur->rcv->snd_una, cur->ack) &&
		!tcp_after(cur->ack, cur->rcv->snd_nxt) ) {

		/* set SND.UNA <- SEG.ACK. */
		dmesg(M_DEBUG, "ack to %.8x", cur->ack);
		cur->rcv->snd_una = cur->ack;

		switch(s->state) {
		case TCP_SESSION_E:
			reassemble_point(s, !cur->to_server, cur->ack);
			break;
		case TCP_SESSION_CF1:
			if ( !cur->to_server ) {
				dmesg(M_DEBUG, "fin+ack for client");
				reassemble_point(s, !cur->to_server,
							cur->ack - 1);
				s->state = TCP_SESSION_CF2;
			}
			break;
		case TCP_SESSION_SF1:
			if ( cur->to_server ) {
				dmesg(M_DEBUG, "fin+ack for server");
				reassemble_point(s, !cur->to_server,
							cur->ack - 1);
				s->state = TCP_SESSION_SF2;
			}
			break;
		case TCP_SESSION_CF3:
			if ( cur->to_server ) {
				dmesg(M_DEBUG, "fin+ack for server");
				reassemble_point(s, !cur->to_server,
							cur->ack - 1);
				s->state = TCP_SESSION_C;
			}
			break;
		case TCP_SESSION_SF3:
			if ( !cur->to_server ) {
				dmesg(M_DEBUG, "fin+ack for client");
				reassemble_point(s, !cur->to_server,
							cur->ack - 1);
				s->state = TCP_SESSION_C;
			}
			break;
		}

		/* the send window should be updated. 
		 * If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and
		 * SND.WL2 =< SEG.ACK)), set SND.WND <- SEG.WND, set
		 * SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK. */
		if ( tcp_before(cur->snd->snd_wl1, cur->seq) ||
			(cur->snd->snd_wl1 == cur->seq &&
				!tcp_after(cur->snd->snd_wl2, cur->ack)) ) {
			dmesg(M_DEBUG, "window update");
			cur->snd->snd_wnd = cur->win;
			cur->snd->snd_wl1 = cur->seq;
			cur->snd->snd_wl2 = cur->ack;
		}
	}

	return 1;
}

static void fin_processing(struct tcpseg *cur, struct tcp_session *s)
{
	assert(cur->tcph->flags & TCP_FIN);

	switch(s->state) {
	case TCP_SESSION_S3:
	case TCP_SESSION_E:
		if ( cur->to_server ) {
			s->state = TCP_SESSION_CF1;
			dmesg(M_DEBUG, "client close first");
		}else{
			s->state = TCP_SESSION_SF1;
			dmesg(M_DEBUG, "server close first");
		}
		break;
	case TCP_SESSION_CF1:
	case TCP_SESSION_CF2:
		if ( cur->to_server ) {
			dmesg(M_DEBUG, "fin resend?");
			return;
		}
		dmesg(M_DEBUG, "server %sclose",
			(s->state == TCP_SESSION_CF1) ? "simultaneous " : "");
		s->state = TCP_SESSION_CF3;
		break;
	case TCP_SESSION_SF1:
	case TCP_SESSION_SF2:
		if ( !cur->to_server ) {
			dmesg(M_DEBUG, "fin resend?");
			return;
		}
		dmesg(M_DEBUG, "client %sclose",
			(s->state == TCP_SESSION_SF1) ? "simultaneous " : "");
		s->state = TCP_SESSION_SF3;
		break;
	default:
		dmesg(M_DEBUG, "FIN in wrong state");
		return;
	}
	cur->snd->snd_nxt++;
}

static int paws_check(struct tcpseg *cur, struct tcp_session *s)
{
	return 1;
}

static void paws_update(struct tcpseg *cur, struct tcp_session *s)
{
}

static void state_track(struct tcpseg *cur, struct tcp_session *s)
{
	if ( s->state == TCP_SESSION_S1 ) {
		if ( cur->to_server ) {
			dmesg(M_DEBUG, "syn resend?");
			timer_msl(cur, s);
		}else{
			s1_processing(cur, s);
		}
		return;
	}

	assert(cur->snd && cur->rcv);

	/* First, check the sequence number */
	if ( !sequence_check(cur, s) ) {
		state_errs++;
		dmesg(M_DEBUG, "Failed sequence check");
		return;
	}

	if ( !paws_check(cur, s) )
		return;

	/* Second, check the RST bit */
	if ( cur->tcph->flags & TCP_RST ) {
		dmesg(M_DEBUG, "connection reset by peer");
		s->state = TCP_SESSION_C;
		return;
	}

	paws_update(cur, s);

	/* Third, check security and precendece (pfft) */

	/* Fourth, check the SYN bit */
	if ( cur->tcph->flags & TCP_SYN ) {
		if ( cur->tcph->flags & TCP_FIN ) {
			dmesg(M_DEBUG, "XMAS attack");
		}
		dmesg(M_DEBUG, "In window SYN");
	}

	cur->win <<= cur->snd->scale;

	set_lru(cur, s);

	/* Fifth, check the ack field */
	if ( cur->tcph->flags & TCP_ACK )
		if ( !ack_processing(cur, s) )
			return;

	/* Sixth Check URG field */
	if ( cur->tcph->flags & TCP_URG ) {
		mesg(M_DEBUG, "URG urgp=%u", sys_be16(cur->tcph->urp));
	}

	/* seventh process the segment text */
	if ( cur->len ) {
		if ( s->state == TCP_SESSION_S3 ) {
			dmesg(M_DEBUG, "%s sent first data",
				cur->to_server ? "client" : "server");
			s->state = TCP_SESSION_E;
			attach_protocol(s);
		}

		cur->snd->snd_una = cur->seq;
		cur->snd->snd_nxt = cur->seq_end;
		dmesg(M_DEBUG, "%u bytes data %.8x - %.8x",
			cur->len, cur->seq, cur->seq_end);
		//dhex_dump(cur->payload, cur->len, 16);
		reasm_data(cur, s);
	}

	/* eighth, check the FIN bit */
	if ( cur->tcph->flags & TCP_FIN )
		fin_processing(cur, s);
}

static int tcp_csum(struct tcpseg *cur)
{
	struct tcp_phdr ph;
	uint16_t *tmp;
	uint32_t sum = 0;
	uint16_t csum, len;
	int i;

	len = sys_be16(cur->iph->tot_len) - (cur->iph->ihl << 2);

	/* Make pseudo-header */
	ph.sip = cur->iph->saddr;
	ph.dip = cur->iph->daddr;
	ph.zero = 0;
	ph.proto = cur->iph->protocol;
	ph.tcp_len = sys_be16(len);

	/* Checksum the pseudo-header */
	tmp = (uint16_t *)&ph;
	for(i = 0; i < 6; i++)
		sum += tmp[i];

	/* Checksum the header+data */
	tmp = (uint16_t *)cur->tcph;
	for(i = 0; i < (len >> 1); i++)
		sum += tmp[i];

	/* Deal with last byte (if odd number of bytes) */
	if ( len & 1 ) {
		union {
			uint8_t b[2];
			uint16_t s;
		}f;

		f.b[0] = ((uint8_t *)cur->tcph)[len - 1];
		f.b[1] = 0;
		sum += f.s;
	}

	sum = (sum & 0xffff) + (sum >> 16);

	csum = ~sum & 0xffff;

	return (csum == 0);
}

static void seg_init(struct tcpseg *cur, pkt_t pkt, struct tcp_dcb *dcb)
{
	cur->ts = pkt->pkt_ts;
	cur->iph = dcb->tcp_iph;
	cur->tcph = dcb->tcp_hdr;
	cur->ack = sys_be32(cur->tcph->ack);
	cur->seq = sys_be32(cur->tcph->seq);
	cur->win = sys_be16(cur->tcph->win);
	cur->hash = tcp_hashfn(cur->iph->saddr, cur->iph->daddr,
				cur->tcph->sport, cur->tcph->dport);
	cur->len = sys_be16(cur->iph->tot_len) -
			(cur->iph->ihl << 2) -
			(cur->tcph->doff << 2);
	cur->seq_end = cur->seq + cur->len;
	cur->tsval = 0;
	cur->saw_tstamp = 0;
	cur->payload = (uint8_t *)cur->tcph + (cur->tcph->doff << 2);

	num_segments++;

	tcp_tmo_check(&tmo_msl, cur->ts);

	dbg_segment(cur);
}

void _tcpflow_track(pkt_t pkt, dcb_t dcb_ptr)
{
	struct tcp_session *s;
	struct tcpseg cur;
	int free = 0;

	seg_init(&cur, pkt, (struct tcp_dcb *)dcb_ptr);

	if ( cur.iph->ttl < minttl ) {
		num_ttl_errs++;
		dmesg(M_DEBUG, "TTL evasion");
		return;
	}

	if ( !tcp_csum(&cur) ) {
		num_csum_errs++;
		dmesg(M_DEBUG, "bad checksum");
		dhex_dump(cur.payload, cur.len, 16);
		return;
	}

	s = tcp_collide(hash[cur.hash],
			cur.iph, cur.tcph, &cur.to_server);
	if ( s == NULL ) {
		s = new_session(&cur);
		if ( s == NULL )
			return;
	}else{
		/* Figure out which side is which */
		if ( cur.to_server ) {
			cur.snd = &s->c_wnd;
			cur.rcv = s->s_wnd;
		}else{
			cur.snd = s->s_wnd;
			cur.rcv = &s->c_wnd;
		}

		tcp_hash_mtf(s, cur.hash);

		state_track(&cur, s);
		if ( s->state == TCP_SESSION_C )
			free = 1;
	}

	dbg_stream("client", &s->c_wnd);
	dbg_stream("server", s->s_wnd);
	if ( free ) {
		tcp_free(s);
		dmesg(M_DEBUG, "freed session state");

	}
	dmesg(M_INFO, "\n");
}

void _tcpflow_dtor(void)
{
	struct tcp_session *s, *tmp;

	list_for_each_entry_safe(s, tmp, &lru, lru)
		tcp_free(s);

	mesg(M_INFO,"tcpstream: errors: %u csum, %u ttl, %u oom, %u timeout",
		num_csum_errs, num_ttl_errs,
		num_oom, num_timeouts);
	mesg(M_INFO,"tcpstream: max_active=%u num_active=%u",
		max_active, num_active);
	mesg(M_INFO,"tcpstream: %u segments processed, %u state errors",
		num_segments, state_errs);
	_tcp_reasm_dtor();
	mempool_free(tcp_pool);
}

int _tcpflow_ctor(void)
{
	size_t flowsz;

	tcp_pool = mempool_new("tcpflow", 1024);

	session_cache = objcache_init(tcp_pool, "tcp_session",
					sizeof(struct tcp_session));
	if ( session_cache == NULL )
		return 0;

	sstate_cache = objcache_init(tcp_pool, "tcp_state",
					sizeof(struct tcp_state));
	if ( sstate_cache == NULL )
		return 0;

	flowsz = stream_max_flow_size(SNS_TCP);
	flow_cache = objcache_init(tcp_pool, "tcp_flow", flowsz);
	if ( flowsz && NULL == flow_cache )
		return 0;

	if ( reassemble && !_tcp_reasm_ctor(tcp_pool) )
		return 0;
	return 1;
}
