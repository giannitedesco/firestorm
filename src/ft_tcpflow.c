/*
 * This file is part of Firestorm NIDS
 * Copyright (c) Gianni Tedesco 2008
 * This program is released under the terms of the GNU GPL version 3
 *
 * TODO:
 *  o Put state data in to DCB
 *  o Handle ICMP errors
 *  o Reassembly
 *  o Application layer infrastructure
 *  o check for broadcasts if possible
*/
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
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
#define dmesg(x...) do{}while(0);
#define dhex_dump(x...) do{}while(0);
#endif

#if SEGMENT_DEBUG
#include <stdio.h>
#include <stdarg.h>
#endif

static const uint8_t minttl = 1;

#define TCP_PAWS_24DAYS (60 * 60 * 24 * 24)
#define TCP_PAWS_MSL 60
#define TCP_PAWS_WINDOW 60

#define TCP_TMO_SYN1 (90 * TIMESTAMP_HZ)

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
	struct tcp_stream *snd, *rcv;
};

#if STATE_DEBUG
static const char * const state_str[] = {
	"CLOSED",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TCP_CLOSE_WAIT",
	"TCP_LAST_ACK",
	"TCP_CLOSING",
	"TCP_TIME_WAIT",
};
#endif

/* Perform a state transition */
static void transition(struct tcp_session *s, int cs, int ss)
{
#if STATE_DEBUG
	ipstr_t sip, cip;

	iptostr(sip, s->s_addr);
	iptostr(cip, s->c_addr);

	mesg(M_DEBUG, "%s:%u(\033[%dm%s\033[0m) -> %s:%u(\033[%dm%s\033[0m)",
		cip, sys_be16(s->c_port), 30 + (cs % 9), state_str[cs],
		sip, sys_be16(s->s_port), 30 + (ss % 9), state_str[ss]);
#endif
	s->client.state = cs;
	s->server.state = ss;
}

static void state_err(struct tcpseg *cur, const char *msg)
{
#if STATE_DEBUG
	ipstr_t sip, dip;

	iptostr(sip, cur->iph->saddr);
	iptostr(dip, cur->iph->daddr);
	mesg(M_ERR, "%s:%u -> %s:%u - %s",
		sip, sys_be16(cur->tcph->sport),
		dip, sys_be16(cur->tcph->dport), msg);
#endif
	cur->tf->state_errs++;
}

/* Wrap-safe seq/ack calculations */
static int between(uint32_t s1, uint32_t s2, uint32_t s3)
{
	return s3 - s2 >= s1 - s2; /* is s2<=s1<=s3 ? */
}

static uint32_t tcp_receive_window(struct tcp_stream *s)
{
	int32_t win = s->rcv_wup + s->rcv_wnd - s->rcv_nxt;
	if ( win < 0 )
		win = 0;
	return (uint32_t)win;
}

static int tcp_sequence(struct tcp_stream *s, uint32_t seq, uint32_t end_seq)
{
	return !tcp_before(end_seq, s->rcv_wup) &&
		!tcp_after(seq, s->rcv_nxt + tcp_receive_window(s));
}

/* Hash function.
 * Hashes to the same value even when source and destinations are inverted.
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
					unsigned int *to_server)
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
			dmesg(M_DEBUG, "Malicious tcp options");
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
			dmesg(M_WARN, "Malicious tcp options");
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
	s->server.isn = cur->seq;
	s->client.snd_una = s->server.isn + 1;
	s->client.snd_nxt = s->client.snd_una + 1;
	s->client.rcv_wnd = cur->win;
	s->server.rcv_nxt = s->client.snd_una;
	s->server.rcv_wup = s->client.snd_una;

	/* server sees clients initial options */
	tcp_syn_options(&s->server, cur->tcph, cur->ts / TIMESTAMP_HZ);

	transition(s, TCP_SYN_SENT, TCP_CLOSED);
	dmesg(M_DEBUG, "#1 - syn");

	return s;
}

static void state_track(struct tcpseg *cur, struct tcp_session *s)
{
	struct tcp_stream *snd = cur->snd, *rcv = cur->rcv;

	if ( snd->state == TCP_SYN_SENT ) {
		dmesg(M_DEBUG, "SYN re-transmit?");
	}else if ( rcv->state == TCP_SYN_SENT &&
		snd->state == TCP_CLOSED ) {
		if ( cur->tcph->flags & TCP_RST ) {
			tcp_free(cur->tf, s);
			dmesg(M_DEBUG, "Connection reset by peer");
			return;
		}
		transition(s, TCP_SYN_RECV, TCP_SYN_SENT);
		dmesg(M_DEBUG, "#2 - syn + ack");
	}else if ( rcv->state == TCP_SYN_SENT &&
			snd->state == TCP_SYN_RECV ) {
		transition(s, TCP_ESTABLISHED, TCP_ESTABLISHED);
		dmesg(M_DEBUG, "#3 - ack");
	}else if ( rcv->state == TCP_ESTABLISHED &&
			snd->state == TCP_ESTABLISHED ) {
		if ( cur->tcph->flags & TCP_FIN ) {
			snd->state = TCP_FIN_WAIT1;
			rcv->state = TCP_CLOSE_WAIT;
			transition(s, s->client.state, s->server.state);
			dmesg(M_DEBUG, "%s initiated close",
				(snd == &s->client) ? "client" : "server");
		}else{
			dmesg(M_DEBUG, "Text segment");
		}
	}else if ( rcv->state == TCP_FIN_WAIT1 ) {
		if ( cur->tcph->flags & TCP_FIN ) {
			rcv->state = TCP_CLOSING;
			snd->state = TCP_LAST_ACK;
			transition(s, s->client.state, s->server.state);
			dmesg(M_DEBUG, "Simultaneous close");
		}else if ( cur->tcph->flags & TCP_ACK ) {
			rcv->state = TCP_FIN_WAIT2;
			transition(s, s->client.state, s->server.state);
			dmesg(M_DEBUG, "Half Open");
		}
	}else if ( rcv->state == TCP_FIN_WAIT2 ) {
		if ( cur->tcph->flags & TCP_FIN ) {
			rcv->state = TCP_TIME_WAIT;
			snd->state = TCP_LAST_ACK;
			transition(s, s->client.state, s->server.state);
			dmesg(M_DEBUG, "Final shutdown");
		}
	}else if ( rcv->state == TCP_LAST_ACK ) {
		if ( cur->tcph->flags & TCP_ACK ) {
			snd->state = TCP_TIME_WAIT;
			rcv->state = TCP_CLOSED;
			/* TODO: Time-wait timer */
			//transition(s, s->client.state, s->server.state);
			tcp_free(cur->tf, s);
			dmesg(M_DEBUG, "Teardown");
		}
	}else if ( rcv->state == TCP_CLOSING || rcv->state == TCP_CLOSE_WAIT ) {
		dmesg(M_DEBUG, "FIN resend");
	}else if ( rcv->state == TCP_TIME_WAIT ) {
		dmesg(M_DEBUG, "ACK or FIN resend");
	}else if ( snd->state == TCP_FIN_WAIT2 ) {
		dmesg(M_DEBUG, "wtf");
	}else{
		assert(0);
	}
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

static void dbg_stream(const char *label, struct tcp_stream *s)
{
#if STREAM_DEBUG
	mesg(M_DEBUG, "\033[34m%s: su=%.8x sn=%.8x n=%.8x wup=%.8x w=%u\033[0m",
		label, s->snd_una, s->snd_nxt,
		s->rcv_nxt, s->rcv_wup, s->rcv_wnd);
#endif
}

void _tcpflow_track(flow_state_t sptr, pkt_t pkt, dcb_t dcb_ptr)
{
	struct ip_flow_state *ipfs = sptr;
	struct tcp_dcb *dcb = (struct tcp_dcb *)dcb_ptr;
	unsigned int to_server;
	struct tcp_session *s;
	struct tcpseg cur;

	cur.tf = &ipfs->tcpflow;

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

	dbg_segment(&cur);

	if ( cur.iph->ttl < minttl ) {
		cur.tf->num_ttl_errs++;
		state_err(&cur, "TTL evasion");
		return;
	}

	if ( !tcp_csum(&cur) ) {
		cur.tf->num_csum_errs++;
		state_err(&cur, "bad checksum");
		dhex_dump(cur.payload, cur.len, 16);
		return;
	}

	s = tcp_collide(cur.tf->hash[cur.hash],
			cur.iph, cur.tcph, &to_server);
	if ( s == NULL ) {
		s = new_session(&cur);
		if ( s == NULL )
			return;
	}else{
		/* Figure out which side is which */
		if ( to_server ) {
			cur.snd = &s->client;
			cur.rcv = &s->server;
		}else{
			cur.snd = &s->server;
			cur.rcv = &s->client;
		}

		tcp_hash_mtf(cur.tf, s, cur.hash);
		list_move(&cur.tf->lru, &s->lru);

		state_track(&cur, s);
	}

	dbg_stream("client", &s->client);
	dbg_stream("server", &s->server);
	//dmesg(M_DEBUG, ".");
}

void _tcpflow_dtor(struct tcpflow *tf)
{
	mesg(M_INFO,"tcpstream: max_active=%u num_active=%u",
		tf->max_active, tf->num_active);
	mesg(M_INFO,"tcpstream: %u state errors out of %u packets",
		tf->state_errs, tf->num_packets);
}

int _tcpflow_ctor(struct tcpflow *tf)
{
	INIT_LIST_HEAD(&tf->lru);
	INIT_LIST_HEAD(&tf->syn1);

	dmesg(M_INFO, "tcpflow: %u bytes state, %u bytes session",
		sizeof(*tf), sizeof(struct tcp_session));

	tf->session_cache = objcache_init("tcp_session",
						sizeof(struct tcp_session));
	if ( tf->session_cache == NULL )
		return 0;

	return 1;
}
