/*
 * This file is part of Firestorm NIDS
 * Copyright (c) Gianni Tedesco 2008
 * This program is released under the terms of the GNU GPL version 3
 *
 * TODO:
 *  o Do checksums, minttl, broadcast check etc...
 *  o Keep track of state-tracking decisions
 *  o Handle ICMP errors
 *  o Reassembly
 *  o Application layer infrastructure
*/
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_flow.h>
#include <pkt/ip.h>
#include <pkt/tcp.h>
#include <pkt/icmp.h>
#include "p_ipv4.h"

#define STATE_DEBUG 0

#if STATE_DEBUG
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do{}while(0);
#define dhex_dump(x...) do{}while(0);
#endif

static const uint8_t minttl = 1;

#define TCP_PAWS_24DAYS (60 * 60 * 24 * 24)
#define TCP_PAWS_MSL 60
#define TCP_PAWS_WINDOW 60

#define TCP_TMO_SYN1 (90 * TIMESTAMP_HZ)

#define TCPHASH 503 /* prime */
struct tcpflow {
	/* flow hash */
	struct list_head lru;
	obj_cache_t session_cache;
	struct tcp_session *hash[TCPHASH];
	struct list_head syn1;

	/* stats */
	unsigned int num_packets;
	unsigned int state_errs;
	unsigned int num_timeouts;
	unsigned int num_active;
	unsigned int max_active;
};

struct tcpseg {
	struct tcpflow *tf;
	timestamp_t ts;
	const struct pkt_iphdr *iph;
	const struct pkt_tcphdr *tcph;
	uint32_t ack, seq, win, seq_end;
	uint16_t hash, len;
	uint32_t tsval;
	unsigned int saw_tstamp;
	uint8_t *payload;
};

#if STATE_DEBUG
static const char * const state_str[] = {
	"CLOSED",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TCP_TIME_WAIT",
	"TCP_CLOSE",
	"TCP_CLOSE_WAIT",
	"TCP_LAST_ACK",
	"TCP_LISTEN",
	"TCP_CLOSING"
};
#endif

/* Perform a state transition */
static void transition(struct tcp_session *s, int cs, int ss)
{
#if STATE_DEBUG
	ipstr_t sip, cip;

	iptostr(sip, s->s_addr);
	iptostr(cip, s->c_addr);

	dmesg(M_DEBUG, "%s:%u(%s) -> %s:%u(%s)",
		cip, sys_be16(s->c_port), state_str[cs],
		sip, sys_be16(s->s_port), state_str[ss]);
#endif
	s->client.state = cs;
	s->server.state = ss;
}

static void state_dbg(struct tcpseg *cur, const char *msg)
{
#if STATE_DEBUG
	ipstr_t sip, dip;

	iptostr(sip, cur->iph->saddr);
	iptostr(dip, cur->iph->daddr);
	mesg(M_DEBUG, "%s:%u -> %s:%u - %s",
		sip, sys_be16(cur->tcph->sport),
		dip, sys_be16(cur->tcph->dport), msg);
#endif
}
static void state_err(struct tcpseg *cur, const char *msg)
{
	ipstr_t sip, dip;

	iptostr(sip, cur->iph->saddr);
	iptostr(dip, cur->iph->daddr);
	//mesg(M_ERR, "%s:%u -> %s:%u - %s",
	//	sip, sys_be16(cur->tcph->sport),
	//	dip, sys_be16(cur->tcph->dport), msg);
	mesg(M_ERR, "%s", msg);
	cur->tf->state_errs++;
}


/* Wrap-safe seq/ack calculations */
static int between(uint32_t s1, uint32_t s2, uint32_t s3)
{
	return s3 - s2 >= s1 - s2; /* is s2<=s1<=s3 ? */
}

static uint32_t tcp_receive_window(struct tcp_stream *tp)
{
	int32_t win = tp->rcv_wup + tp->rcv_wnd - tp->rcv_nxt;
	if ( win < 0 )
		win = 0;
	return (uint32_t)win;
}

static int tcp_sequence(struct tcp_stream *tp, uint32_t seq, uint32_t end_seq)
{
	return !tcp_before(end_seq, tp->rcv_wup) &&
		!tcp_after(seq, tp->rcv_nxt + tcp_receive_window(tp));
}

/* Hash function. Hashes to the same value even when source
 * and destinations are inverted 
 */
static uint16_t _constfn tcp_hashfn(uint32_t saddr, uint32_t daddr,
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
static void tcp_hash_link(struct tcpflow *tf, struct tcp_session *s,
				uint16_t bucket)
{
	if ((s->hash_next = tf->hash[bucket]))
		s->hash_next->hash_pprev = &s->hash_next;
	tf->hash[bucket] = s;
	s->hash_pprev = &tf->hash[bucket];
}

/* HASH: Move to front of hash collision chain */
static void tcp_hash_mtf(struct tcpflow *tf, struct tcp_session *s,
				uint16_t bucket)
{
	tcp_hash_unlink(s);
	tcp_hash_link(tf, s, bucket);
}

/* Find a TCP session given a packet */
static struct tcp_session *tcp_collide(struct tcp_session *s,
					const struct pkt_iphdr *iph,
					const struct pkt_tcphdr *tcph,
					int *to_server)
{
	for (; s; s = s->hash_next) {
		if (	s->s_addr == iph->saddr &&
			s->c_addr == iph->daddr &&
			s->s_port == tcph->sport &&
			s->c_port == tcph->dport ) {
			*to_server = 0;
			return s;
		}
		if (	s->c_addr == iph->saddr &&
			s->s_addr == iph->daddr &&
			s->c_port == tcph->sport &&
			s->s_port == tcph->dport ) {
			*to_server = 1;
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
			state_dbg(cur, "Malicious tcp options");
			step = 2;
		}
		tmp += step;
	}

	return 0;
}

/* This will parse TCP options for SYN packets */
static void tcp_syn_options(struct tcp_stream *s,
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
			//state_dbg(cur, "Malicious tcp options");
			step = 2;
		}

		tmp += step;
	}
}

static void tcp_free(struct tcpflow *tf, struct tcp_session *s)
{
	transition(s, 0, 0);
	tcp_hash_unlink(s);
	list_del(&s->tmo);
	list_del(&s->lru);
	objcache_free(tf->session_cache, s);
	tf->num_active--;
}

/* TMO: Check timeouts */
static void tcp_tmo_check(struct tcpflow *tf, timestamp_t now)
{
	struct tcp_session *s;

	/* Actually, the generic list API made this more ugly */
	while ( !list_empty(&tf->syn1) ) {
		s = list_entry(tf->syn1.prev, struct tcp_session, tmo);
		if ( !time_before(s->expire, now) )
			return;

		tcp_free(tf, s);
		tf->num_timeouts++;
	}
}

/* TMO: Set expiry */
static void tcp_expire(struct tcpflow *tf,
				struct tcp_session *s,
				timestamp_t t)
{
	s->expire = t;
	list_move(&tf->syn1, &s->tmo);
}

static struct tcp_session *tcp_new(struct tcpseg *cur)
{
	struct tcp_session *s;

	/* Track syn packets only for now. This could be re-jiggled for
	 * flow accounting:
	 *  - move this check after allocation
	 *  - for stray packets: don't transition + keep server/client zeroed
	 */
	if ( (cur->tcph->flags & (TCP_SYN|TCP_ACK|TCP_RST)) != TCP_SYN ) {
		state_err(cur, "not a valid syn packet");
		return NULL;
	}

	/* timeout check: assumes time is monotonic */
	tcp_tmo_check(cur->tf, cur->ts);

	/* FIXME: evict one if necessary */
	s = objcache_alloc(cur->tf->session_cache);
	if ( s == NULL ) {
		mesg(M_CRIT, "tcp OOM");
		return NULL;
	}

	s->c_addr = cur->iph->saddr;
	s->s_addr = cur->iph->daddr;
	s->c_port = cur->tcph->sport;
	s->s_port = cur->tcph->dport;

	/* link it all up and set the SYN1 timeout */
	list_add(&s->lru, &cur->tf->lru);
	tcp_hash_link(cur->tf, s, cur->hash);
	INIT_LIST_HEAD(&s->tmo);
	tcp_expire(cur->tf, s, cur->ts + TCP_TMO_SYN1);

	/* stats */
	cur->tf->num_active++;
	if ( cur->tf->num_active > cur->tf->max_active )
		cur->tf->max_active = cur->tf->num_active;

	/* Setup initial window tracking state machine */
	memset(&s->client, 0, sizeof(s->client));
	memset(&s->server, 0, sizeof(s->server));
	transition(s, TCP_SYN_SENT, 0);
	s->server.isn = cur->seq;
	s->client.snd_una = s->server.isn + 1;
	s->client.snd_nxt = s->client.snd_una + 1;
	s->client.rcv_wnd = cur->win;
	s->server.rcv_nxt = s->client.snd_una;
	s->server.rcv_wup = s->client.snd_una;

	/* server sees clients initial options */
	tcp_syn_options(&s->server, cur->tcph, cur->ts / TIMESTAMP_HZ);

	/* TODO */
	s->proto = NULL;

	return s;
}

/* rfc793: Actions to perform when recieving an ACK in
 * an established state */
static void tcp_data_ack(struct tcp_stream *snd, struct tcp_stream *rcv,
				uint32_t seq, uint32_t ack, uint32_t win)
{
	snd->snd_una = seq;
	snd->snd_nxt = seq + 1;

	snd->rcv_wup = ack;
	snd->rcv_wnd = win;

	if ( tcp_after(ack, rcv->snd_una) && !tcp_before(ack, rcv->snd_nxt) ) {
		rcv->snd_una = ack;

		/* Try to reassemble up to acked byte */
		/* XXX: Can only deliver data to user if rcv is in one of
		 * ESTABLISHED, FIN_WAIT1 or FIN_WAIT2. That means we have
		 * to hold on to any data until connection establishment.
		 */
		if ( (rcv->state >= TCP_FIN_WAIT1) &&
			(rcv->state != TCP_LISTEN) )
			--ack;

		//reassemble_point(cur.sndbuf, ack);
	}
}

static void state_track(struct tcpseg *cur)
{
	struct tcp_session *s;
	struct tcp_stream *snd, *rcv;
	int to_server;

	s = tcp_collide(cur->tf->hash[cur->hash],
			cur->iph, cur->tcph, &to_server);
	if ( s == NULL ) {
		s = tcp_new(cur);
		return;
	}

	tcp_hash_mtf(cur->tf, s, cur->hash);
	list_move(&cur->tf->lru, &s->lru);

	/* Figure out which side is which */
	if ( to_server ) {
		snd = &s->client;
		rcv = &s->server;
	}else{
		snd = &s->server;
		rcv = &s->client;
	}

	/* Deal with a SYN/ACK */
	if ( rcv->state == TCP_SYN_SENT ) {
		/* fist check the ack field */
		if ( cur->tcph->flags & TCP_ACK ) {
		 	/* if SND.UNA =< SEG.ACK =< SND.NXT
			 * then ACK is acceptable */
			if ( !(between(cur->ack,
					rcv->snd_una, rcv->snd_nxt)) ) {
				state_err(cur, "syn+ack bad ack");
				return;
			}

			/* Dodgy heuristic for swapped SYN+ACK/ACK */
#if 0
			if ( (rcv->rcv_nxt == 0) ) {
				state_dbg(cur, "doing dodgy heuristic");
				rcv->rcv_nxt = cur->seq_end;
				rcv->state = TCP_SYN_RECV;
				snd->state = TCP_SYN_SENT;
				transition(s, s->client.state, s->server.state);
			}
#endif
		}

		/* then check the rst flag */
		if ( cur->tcph->flags & TCP_RST ) {
			tcp_free(cur->tf, s);
			state_dbg(cur, "connection refused");
			return;
		}

		if ( cur->tcph->flags & TCP_SYN ) {
			/* update the advertised window */
			snd->rcv_wnd = cur->win;

			/* update sequencing information */
			snd->snd_una = cur->seq + 1;
			snd->snd_nxt = snd->snd_una + 1;

			rcv->isn = cur->seq;
			rcv->rcv_nxt = cur->seq_end;
			rcv->rcv_wup = cur->seq_end;
			if ( cur->tcph->flags & TCP_ACK )
				rcv->snd_una = cur->ack;

			/* client now sees servers initial options */
			tcp_syn_options(&s->client, cur->tcph,
					cur->ts / TIMESTAMP_HZ);

			/* Check whether to use window scaling */
			if ( !(rcv->flags & TF_WSCALE_OK) ||
				!(snd->flags & TF_WSCALE_OK) ) {
				rcv->scale = 0;
				snd->scale = 0;
			}

			/* SYN|ACK: part 2 of connection handshake */
			rcv->state = TCP_SYN_RECV;
			snd->state = TCP_SYN_SENT;
			transition(s, s->client.state, s->server.state);
			list_del(&s->tmo);

			return;
		}else
			goto no_checks;
	}

	/* First check the sequence number (catches retransmits) */
	if ( !tcp_sequence(rcv, cur->seq, cur->seq_end) ) {
		/* ERROR - 7208 */
		state_err(cur, "failed sequence check");
		return;
	}

no_checks:
	/* rfc1323: H1. Apply PAWS checks first */
	if ( (rcv->flags & TF_TSTAMP_OK) &&
		(cur->saw_tstamp = tcp_fast_options(cur)) ) {
		/* TODO: PAWS is buggy as fuck. We use the Linux PAWS check,
		 * I have no idea what other stacks do...
		 */
		if ( (int32_t)(rcv->ts_recent - cur->tsval) > TCP_PAWS_WINDOW &&
			(uint32_t)(cur->ts/TIMESTAMP_HZ) < rcv->ts_recent_stamp
			+ TCP_PAWS_24DAYS ) {
			state_err(cur, "PAWS discard");
			return;
		}
	}

	/* Second, check the RST bit */
	if ( cur->tcph->flags & TCP_RST ) {
		state_dbg(cur, "TCP stream was reset");
		tcp_free(cur->tf, s);
		return;
	}

	/* rfc1323: PAWS: update ts_recent */
	if ( cur->saw_tstamp && !tcp_after(cur->seq,rcv->rcv_wup) ) {
		if((int32_t)(cur->tsval - rcv->ts_recent) >= 0 ||
		   (uint32_t)(cur->ts / TIMESTAMP_HZ) >= rcv->ts_recent_stamp
		   + TCP_PAWS_24DAYS) {
			rcv->ts_recent = cur->tsval;
			rcv->ts_recent_stamp = cur->ts / TIMESTAMP_HZ;
		}
	}

	/* Third, check security and precendece (pfft) */

	/* Fourth, check the SYN bit */
	if ( cur->tcph->flags & TCP_SYN && !tcp_before(cur->seq,rcv->rcv_nxt) ) {
		/* If not a retransmit, then it's an in-window SYN */
		if ( cur->seq != rcv->isn)
			state_dbg(cur, "in window syn");

		//state_err(cur, "unknown syn thing");
		tcp_free(cur->tf, s);
		return;
	}

	/* we now know that this packet is in-state */

	/* Scale the window */
	cur->win <<= snd->scale;

	/* Fifth, check the ack field */
	if ( (cur->tcph->flags & TCP_ACK) == 0 )
		goto no_ack;

	switch(rcv->state) {
	case TCP_SYN_SENT:
		/* First ACK: part 3 of connection handshake */
		if ( !tcp_after(rcv->snd_una, cur->ack) &&
			!tcp_after(cur->ack, rcv->snd_nxt) ) {
			tcp_data_ack(snd, rcv, cur->seq, cur->ack, cur->win);
			transition(s, TCP_ESTABLISHED, TCP_ESTABLISHED);
		}
		break;
	case TCP_ESTABLISHED:
		tcp_data_ack(snd,rcv, cur->seq, cur->ack, cur->win);
		break;
	case TCP_FIN_WAIT1:
		tcp_data_ack(snd,rcv, cur->seq, cur->ack,cur->win);
		rcv->state = TCP_FIN_WAIT2;
		snd->state = TCP_LAST_ACK;
		transition(s, s->client.state, s->server.state);
	case TCP_FIN_WAIT2:
		//reassemble_point(cur.sndbuf, cur->ack - 1);
		break;
	case TCP_CLOSE_WAIT:
		tcp_data_ack(snd, rcv, cur->seq, cur->ack, cur->win);
		break;
	case TCP_CLOSING:
		tcp_data_ack(snd, rcv, cur->seq, cur->ack, cur->win);
		rcv->state = TCP_TIME_WAIT;
		transition(s, s->client.state, s->server.state);
		break;
	case TCP_LAST_ACK:
		/* XXX: is this one needed? */
		//reassemble_point(cur.sndbuf, cur->ack - 1);
		rcv->state = 0;
		transition(s, s->client.state, s->server.state);
		break;
	default:
		break;
	}

no_ack:
	/* sixth check URG bit */

	/* seventh process the segment text */
	if ( cur->len == 0 )
		goto no_data;

	/* There is data in the segment */
	switch(rcv->state) {
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
	case TCP_TIME_WAIT:
		state_dbg(cur, "data sent on closed stream");
		goto no_data;
	}

	if ( !tcp_after(cur->seq_end, rcv->rcv_nxt) )
		goto no_data;

	if ( !tcp_after(cur->seq, rcv->rcv_nxt) ) {
		//if (tcp_receive_window(rcv) == 0) {
		//	/* XXX: Alert here? */
		//	goto no_data;
		//}

		rcv->rcv_nxt = cur->seq_end;
	}

	//dhex_dump(cur->payload, cur->len, 16);

no_data:
	/* eighth, check the FIN bit */
	if ( (cur->tcph->flags & TCP_FIN) == 0 )
		goto no_fin;

	rcv->rcv_nxt++;

	switch(rcv->state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
		rcv->state = TCP_CLOSE_WAIT;
		snd->state = TCP_FIN_WAIT1;
		transition(s, s->client.state, s->server.state);
		break;
	case TCP_FIN_WAIT1:
		/* if fin has been acked do time_wait else closing */
		rcv->state = TCP_TIME_WAIT;
		transition(s, s->client.state, s->server.state);
		break;
	case TCP_FIN_WAIT2:
		rcv->state = TCP_TIME_WAIT;
		transition(s, s->client.state, s->server.state);
		break;
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
	case TCP_TIME_WAIT:
		/* Remain in the same state */
		break;
	default:
		break;
	}

no_fin:
	/* TODO: need to implement time_wait timer */
	if ( (snd->state == TCP_TIME_WAIT && rcv->state == 0) ||
		(rcv->state == TCP_TIME_WAIT && snd->state == 0) ) {
		tcp_free(cur->tf, s);
		state_dbg(cur, "connection closed");
		return;
	}else if ( rcv->state == 0 && snd->state == TCP_SYN_SENT ) {
		/* we reset the timeout on retransmissions */
		if ( (cur->tcph->flags &
				(TCP_SYN|TCP_ACK|TCP_RST)) == TCP_SYN ) {
			state_dbg(cur, "syn1 timer reset by retransmit");
			tcp_expire(cur->tf, s, cur->ts + TCP_TMO_SYN1);
		}
	}

	return;
}

/* FIXME: most of this stack frame ought to go in a struct and pass pointer */
static pkt_t tcpflow_track(flow_state_t sptr, pkt_t pkt, dcb_t dcb_ptr)
{
	struct tcp_dcb *dcb = (struct tcp_dcb *)dcb_ptr;
	struct tcpseg cur;

	cur.tf = sptr;
	cur.ts = pkt->pkt_ts;
	cur.iph = dcb->tcp_iph;
	cur.tcph = dcb->tcp_hdr;
	cur.ack = sys_be32(cur.tcph->ack);
	cur.seq = sys_be32(cur.tcph->seq);
	cur.win = sys_be16(cur.tcph->win);
	cur.hash = tcp_hashfn(cur.iph->saddr, cur.iph->daddr,
				cur.tcph->sport, cur.tcph->dport);
	cur.len = sys_be16(cur.iph->tot_len) -
			(cur.iph->ihl << 2) -
			(cur.tcph->doff << 2);
	cur.seq_end = cur.seq + cur.len;
	cur.tsval = 0;
	cur.saw_tstamp = 0;
	cur.payload = (uint8_t *)cur.tcph + (cur.tcph->doff << 2);

	cur.tf->num_packets++;

	state_track(&cur);

	return NULL;
}

static void tcpflow_dtor(flow_state_t s)
{
	struct tcpflow *tf = s;
	mesg(M_INFO,"tcpstream: max_active=%u num_active=%u",
		tf->max_active, tf->num_active);
	mesg(M_INFO,"tcpstream: %u state errors out of %u packets",
		tf->state_errs, tf->num_packets);
	free(tf);
}

static flow_state_t tcpflow_ctor(memchunk_t mc)
{
	struct tcpflow *tf;

	tf = calloc(1, sizeof(*tf));
	if ( tf == NULL )
		return NULL;

	INIT_LIST_HEAD(&tf->lru);
	INIT_LIST_HEAD(&tf->syn1);

	dmesg(M_INFO, "tcpflow: %u bytes state, %u bytes session",
		sizeof(*tf), sizeof(struct tcp_session));

	tf->session_cache = objcache_init(mc, "tcp_session",
						sizeof(struct tcp_session));
	if ( tf->session_cache == NULL ) {
		free(tf);
		tf = NULL;
	}

	return tf;
}

struct _flow_tracker _ipv4_tcpflow = {
	.ft_label = "tcpflow",
	.ft_ctor = tcpflow_ctor,
	.ft_dtor = tcpflow_dtor,
	.ft_track = tcpflow_track,
};
