/* Copyright (c) Gianni Tedesco 2009
 * Author: Gianni Tedesco (gianni at scaramanga dot co dot uk)
 *
 * This is a fast tcp stream reassembly module which manages allocation of
 * contiguous chunks of memory (say 2 to the power of 7-9 bytes).
*/
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <list.h>
#include <p_tcp.h>
#include <pkt/tcp.h>
#include "tcpip.h"

#if 0
#define dmesg mesg
#else
#define dmesg(x...) do { } while(0);
#endif

#define RBUF_SHIFT	8
#define RBUF_SIZE	(1<<RBUF_SHIFT)
#define RBUF_MASK	(RBUF_SIZE - 1)
#define RBUF_BASE	(~RBUF_MASK)

struct tcp_rbuf {
	/** List entry */
	struct list_head	r_list;
	/** sequence number of first byte of buffer */
	uint32_t		r_seq;
	/** buffer base pointer */
	uint8_t			*r_base;
};

struct tcp_gap {
	uint32_t 		g_begin;
	uint32_t 		g_end;
};

/* Reassembly buffer */
#define TCP_REASM_MAX_GAPS	8
struct tcp_sbuf {
	/** begin seq for buffer purposes */
	uint32_t		s_begin;
	/** Sequence of first byte not reassembled */
	uint32_t		s_reasm_begin;
	/** sequence number of last contig byte */
	uint32_t 		s_contig_seq;
	/** Sequence number of last byte */
	uint32_t		s_end;
	/** Buffer list */
	struct list_head	s_bufs;
	/** last contiguous buffer */
	struct tcp_rbuf		*s_contig;
	/** Number of allocated rbufs */
	uint16_t		s_num_rbuf;
	/** number of gaps in reassembly */
	uint8_t			s_num_gaps;
	uint8_t			_pad0;
	/** array of gap descriptors */
	struct tcp_gap		*s_gap[TCP_REASM_MAX_GAPS];
};

static objcache_t sbuf_cache;
static objcache_t rbuf_cache;
static objcache_t data_cache;
static objcache_t gap_cache;
static unsigned int max_gaps;
static unsigned int num_reasm;
static unsigned int num_push;
static uint64_t push_bytes;

static uint32_t seq_base(struct tcp_sbuf *s, uint32_t seq)
{
	return s->s_begin + (tcp_diff(s->s_begin, seq) & RBUF_BASE);
}

static uint32_t seq_ofs(struct tcp_sbuf *s, uint32_t seq)
{
	return tcp_diff(s->s_begin, seq) & RBUF_MASK;
}

static void gap_free(struct tcp_gap *g)
{
	objcache_free2(gap_cache, g);
}

static inline uint32_t gap_len(struct tcp_gap *g)
{
	assert(tcp_after(g->g_end, g->g_begin));
	return tcp_diff(g->g_begin, g->g_end);
}

static struct tcp_rbuf *rbuf_alloc(struct tcp_session *ss,
					struct tcp_sbuf *s, uint32_t seq)
{
	struct tcp_rbuf *r;
	assert(((seq - s->s_begin) & RBUF_MASK) == 0);
	r = _tcp_alloc(ss, rbuf_cache, 1);
	if ( r ) {
		s->s_num_rbuf++;
		INIT_LIST_HEAD(&r->r_list);
		r->r_seq = seq;
		r->r_base = _tcp_alloc(ss, data_cache, 1);
		if ( NULL == r->r_base ) {
			objcache_free2(rbuf_cache, r);
			return NULL;
		}
		dmesg(M_DEBUG, " Allocated rbuf %u seq=%u",
			s->s_num_rbuf, seq);
	}
	return r;
}

static void rbuf_free(struct tcp_sbuf *s, struct tcp_rbuf *r)
{
	list_del(&r->r_list);
	objcache_free2(data_cache, r->r_base);
	objcache_free2(rbuf_cache, r);
	s->s_num_rbuf--;
}

static struct tcp_rbuf *rbuf_next(struct tcp_sbuf *s, struct tcp_rbuf *r)
{
	if ( r->r_list.next == &s->s_bufs )
		return NULL;
	return list_entry(r->r_list.next, struct tcp_rbuf, r_list);
}

static struct tcp_rbuf *rbuf_prev(struct tcp_sbuf *s, struct tcp_rbuf *r)
{
	if ( r->r_list.prev == &s->s_bufs )
		return NULL;
	return list_entry(r->r_list.prev, struct tcp_rbuf, r_list);
}

/* Allocates a new gap ready for insertion in to the tree with the given
 * particulars.
 */
static struct tcp_gap *gap_new(struct tcp_session *ss,
				uint32_t begin, uint32_t end)
{
	struct tcp_gap *g;

	assert(!tcp_after(begin, end));

	g = _tcp_alloc(ss, gap_cache, 1);
	if ( NULL != g ) {
		g->g_begin = begin;
		g->g_end = end;
	}

	return g;
}

static struct tcp_rbuf *first_buffer(struct tcp_sbuf *s)
{
	if ( list_empty(&s->s_bufs) )
		return NULL;
	return list_entry(s->s_bufs.next, struct tcp_rbuf, r_list);
}

static struct tcp_rbuf *last_buffer(struct tcp_sbuf *s)
{
	if ( list_empty(&s->s_bufs) )
		return NULL;
	return list_entry(s->s_bufs.prev, struct tcp_rbuf, r_list);
}

static struct tcp_rbuf *find_buf_fwd(struct tcp_session *ss,struct tcp_sbuf *s,
					struct tcp_rbuf *r, uint32_t seq)
{
	struct tcp_rbuf *new;

	for(; r; r = rbuf_next(s, r)) {
		if ( r->r_seq == seq )
			break;
		if ( tcp_after(r->r_seq, seq) ) {
			new = rbuf_alloc(ss, s, seq);
			if ( NULL == new )
				return NULL;
			list_add_tail(&new->r_list, &r->r_list);
			r = new;
			break;
		}
	}

	if ( NULL == r ) {
		new = rbuf_alloc(ss, s, seq);
		if ( NULL == new )
			return NULL;
		list_add_tail(&new->r_list, &s->s_bufs);
		r = new;
	}

	return r;
}

static struct tcp_rbuf *find_buf_rev(struct tcp_session *ss, struct tcp_sbuf *s,
					struct tcp_rbuf *r, uint32_t seq)
{
	struct tcp_rbuf *new;

	for(; r; r = rbuf_prev(s, r)) {
		if ( r->r_seq == seq )
			break;
		if ( tcp_before(r->r_seq, seq) ) {
			new = rbuf_alloc(ss, s, seq);
			if ( NULL == new )
				return NULL;
			list_add(&new->r_list, &r->r_list);
			r = new;
			break;
		}
	}

	if ( NULL == r ) {
		new = rbuf_alloc(ss, s, seq);
		if ( NULL == new )
			return NULL;
		list_add_tail(&new->r_list, &s->s_bufs);
		r = new;
	}

	return r;
}

static struct tcp_rbuf *contig_buf(struct tcp_session *ss,
					struct tcp_sbuf *s, uint32_t seq)
{
	struct tcp_rbuf *r;

	r = (s->s_contig) ? s->s_contig : first_buffer(s);
	return find_buf_fwd(ss, s, r, seq);
}

static struct tcp_rbuf *discontig_buf(struct tcp_session *ss,
					struct tcp_sbuf *s, uint32_t seq)
{
	struct tcp_rbuf *r;
	r = find_buf_rev(ss, s, last_buffer(s), seq);
	return r;
}

static void swallow_gap(struct tcp_sbuf *s, unsigned int i)
{
	dmesg(M_DEBUG, "Swallow gap %u %u-%u", i,
		s->s_gap[i]->g_begin, s->s_gap[i]->g_end);
	gap_free(s->s_gap[i]);
	for(--s->s_num_gaps; i < s->s_num_gaps; i++) {
		dmesg(M_DEBUG, " Shuffle gap %u to %u", i + 1, i);
		s->s_gap[i] = s->s_gap[i + 1];
	}
}

static void contig_eat_gaps(struct tcp_sbuf *s,
				uint32_t seq_end)
{
	unsigned int i = 0;
	struct tcp_gap *g = NULL;

	while(s->s_num_gaps) {
		g = s->s_gap[0];

		if ( tcp_before(seq_end, g->g_begin) )
			break;
		if ( tcp_before(seq_end, g->g_end) ) {
			g->g_begin = seq_end;
			break;
		}
		swallow_gap(s, i);
		g = NULL;
	}

	if ( g ) {
		dmesg(M_DEBUG, " new contig_seq: %u -> %u",
			s->s_contig_seq, g->g_begin);
		s->s_contig_seq = g->g_begin;
	}else{
		dmesg(M_DEBUG, " new contig_seq: %u -> %u (buffer contig)",
			s->s_contig_seq, seq_end);
		if ( tcp_after(seq_end, s->s_end) )
			s->s_contig_seq = seq_end;
		else
			s->s_contig_seq = s->s_end;
	}
}

static int append_gap(struct tcp_session *ss, struct tcp_sbuf *s,
			struct tcp_rbuf *r, uint32_t seq, uint32_t seq_end)
{
	dmesg(M_DEBUG, "Appending gap %u-%u", s->s_end, seq);
	if (s->s_num_gaps >= TCP_REASM_MAX_GAPS) {
		mesg(M_CRIT, "tcp_reasm: MAX_GAPS exceeded");
		return 0;
	}
	s->s_gap[s->s_num_gaps] = gap_new(ss, s->s_end, seq);
	if ( ++s->s_num_gaps > max_gaps )
		max_gaps = s->s_num_gaps;
	return 1;
}

static int split_gap(struct tcp_session *ss, struct tcp_sbuf *s,
			int i, struct tcp_rbuf *r,
			uint32_t seq, uint32_t seq_end)
{
	int n, j;

	if (s->s_num_gaps >= TCP_REASM_MAX_GAPS) {
		mesg(M_CRIT, "tcp_reasm: MAX_GAPS exceeded");
		return 0;
	}

	dmesg(M_DEBUG, "Split gap");
	for(n = i + 1, j = s->s_num_gaps; j > n; --j) {
		dmesg(M_DEBUG, " Shuffle gap %d to %d", j - 1, j);
		s->s_gap[j] = s->s_gap[j - 1];
	}

	dmesg(M_DEBUG, " gap %d-%u: %u-%u -> (%u-%u, %u-%u)", i, n,
		s->s_gap[i]->g_begin, s->s_gap[i]->g_end,
		s->s_gap[i]->g_begin, seq,
		seq_end, s->s_gap[i]->g_end);

	s->s_gap[n] = gap_new(ss, seq_end, s->s_gap[i]->g_end);
	s->s_gap[i]->g_end = seq;
	if ( ++s->s_num_gaps > max_gaps )
		max_gaps = s->s_num_gaps;
	return 1;
}

static int frob_gaps(struct tcp_session *ss, struct tcp_sbuf *s,
			struct tcp_rbuf *r, uint32_t seq, uint32_t seq_end)
{
	unsigned int i;

	for(i = 0; i < s->s_num_gaps; i++) {
		struct tcp_gap *g = s->s_gap[i];
		if ( tcp_after(seq, g->g_begin) ) {
			if ( tcp_after(seq, g->g_end) )
				continue;

			/* There can be...only one */
			if ( tcp_before(seq_end, g->g_end) ) {
				if ( !split_gap(ss, s, i, r, seq, seq_end) )
					return 0;
				return 1;
			}

			dmesg(M_DEBUG, "Backward overlap");
			dmesg(M_DEBUG, " %u-%u -> %u-%u",
				g->g_begin, g->g_end,
				g->g_begin, seq);
			g->g_end = seq;
		}else{
			if ( tcp_after(g->g_begin, seq) )
				break;

			if ( !tcp_before(seq_end, g->g_end) ) {
				swallow_gap(s, i);
				i--;
				continue;
			}

			dmesg(M_DEBUG, "Forward overlap");
			dmesg(M_DEBUG, " %u-%u -> %u-%u",
				g->g_begin, g->g_end,
				seq_end, g->g_end);
			g->g_begin = seq_end;
		}
	}
	return 1;
}

/* input packet data in to the reassembly system */
static int do_inject(struct tcp_session *ss, struct tcp_sbuf *s,
			uint32_t seq, uint32_t len, const uint8_t *buf)
{
	uint32_t seq_end = seq + len;
	uint32_t base, ofs, clen, sseq;
	int is_contig;
	struct tcp_rbuf *r, *lr;

	if ( NULL == s )
		return 1;

	dmesg(M_DEBUG, "Inject Packet: %u - %u",
		seq, seq + len);

	/* Discard everything before contig_seq */
	if ( tcp_before(seq_end, s->s_contig_seq) )
		return 1;
	if ( tcp_before(seq, s->s_contig_seq) ) {
		uint32_t d = tcp_diff(seq, s->s_contig_seq);
		seq += d;
		buf += d;
		len -= d;
	}
	if ( len == 0 )
		return 1;

	dmesg(M_DEBUG, " Trimmed data: %u - %u",
		seq, seq + len);

	/* Find or allocate buffer for first byte */
	base = seq_base(s, seq);
	if ( seq == s->s_contig_seq ) {
		r = contig_buf(ss, s, base);
		if ( NULL == r )
			return 0;
		contig_eat_gaps(s, seq_end);
		is_contig = 1;
	}else{
		assert(tcp_after(seq, s->s_contig_seq));
		is_contig = 0;
		r = discontig_buf(ss, s, base);
		if ( NULL == r )
			return 0;
		if ( tcp_after(seq, s->s_end) ) {
			if ( !append_gap(ss, s, r, seq, seq_end) )
				return 0;
		}else{
			if ( !frob_gaps(ss, s, r, seq, seq_end) )
				return 0;
		}
	}

	/* Copy payload data, allocating new buffers as needed */
	dmesg(M_DEBUG, "Copying data to buffers:");
	for(sseq = seq; tcp_before(sseq, seq_end); r = rbuf_next(s, r)) {
		struct tcp_rbuf *nr;

		base = seq_base(s, sseq);
		ofs = seq_ofs(s, sseq);
		clen = ((ofs + len) > RBUF_SIZE) ? (RBUF_SIZE - ofs) : len;

		if ( NULL == r ) {
			nr = rbuf_alloc(ss, s, base);
			if ( NULL == nr )
				return 0;
			list_add_tail(&nr->r_list, &s->s_bufs);
			r = nr;
		}else if ( tcp_after(base, r->r_seq) ) {
			nr = rbuf_alloc(ss, s, base);
			if ( NULL == nr )
				return 0;
			dmesg(M_DEBUG, " ... and put it after %u", r->r_seq);
			list_add(&nr->r_list, &r->r_list);
			r = nr;
		}else if ( tcp_before(base, r->r_seq) ) {
			nr = rbuf_alloc(ss, s, base);
			if ( NULL == nr )
				return 0;
			dmesg(M_DEBUG, " ... and put it before %u", r->r_seq);
			list_add_tail(&nr->r_list, &r->r_list);
			r = nr;
		}

		dmesg(M_DEBUG, " Copy data: base=%u:%u ofs=%u len=%u",
			r->r_seq, base, ofs, clen);
		assert(r->r_seq == base);

		memcpy(r->r_base + ofs, buf, clen);
		lr = r;

		if ( is_contig )
			s->s_contig = r;

		sseq += clen;
		buf += clen;
		len -= clen;

		assert(!tcp_after(sseq, seq_end));
	}

	if ( tcp_after(seq_end, s->s_end) ) {
		dmesg(M_DEBUG, " Setting seq_end to %u", seq_end);
		s->s_end = seq_end;
	}
	return 1;
}

static void sbuf_free(struct tcp_session *ss, struct tcp_sbuf *s)
{
	struct tcp_rbuf *r, *tr;
	unsigned int i;

	if ( NULL == s )
		return;

	if ( s->s_bufs.prev ) {
		list_for_each_entry_safe(r, tr, &s->s_bufs, r_list) {
			rbuf_free(s, r);
		}
	}

	for(i = 0; i < s->s_num_gaps; i++)
		gap_free(s->s_gap[i]);

	objcache_free2(sbuf_cache, s);
}

static struct tcp_sbuf *sbuf_new(struct tcp_session *ss, uint32_t isn)
{
	struct tcp_sbuf *s;

	s = _tcp_alloc(ss, sbuf_cache, 1);
	if ( s ) {
		s->s_begin = isn;
		s->s_reasm_begin = isn;
		s->s_end = isn;
		INIT_LIST_HEAD(&s->s_bufs);
		s->s_contig = NULL;
		s->s_contig_seq = isn;
		s->s_num_gaps = 0;
		s->s_num_rbuf = 0;
	}

	return s;
}

static void do_abort(struct tcp_session *s, int rst)
{
	dmesg(M_DEBUG, "Aborting seshion with%s RST packet",
		(rst) ? "" : "out");
	if ( s->c_wnd.reasm ) {
		sbuf_free(s, s->c_wnd.reasm);
		s->c_wnd.reasm = NULL;
	}
	if ( s->s_wnd && s->s_wnd->reasm ) {
		sbuf_free(s, s->s_wnd->reasm);
		s->s_wnd->reasm = NULL;
	}
	if ( s->app )
		s->app->a_fini(s);
	s->app = NULL;
	s->flow = NULL;
}

static void do_data(struct tcp_session *s, uint8_t to_server,
			uint32_t seq, uint32_t len, const uint8_t *buf)
{
	int ret;

	if ( to_server ) {
		ret = do_inject(s, s->c_wnd.reasm, seq, len, buf);
	}else{
		ret = do_inject(s, s->s_wnd->reasm, seq, len, buf);
	}

	if ( !ret )
		do_abort(s, 0);
}

static int alloc_reasm_buffers(struct tcp_session *s)
{
	s->c_wnd.reasm = sbuf_new(s, s->c_wnd.snd_nxt);
	if ( NULL == s->c_wnd.reasm )
		return 0;

	s->s_wnd->reasm = sbuf_new(s, s->s_wnd->snd_nxt);
	if ( NULL == s->s_wnd->reasm ) {
		sbuf_free(s, s->c_wnd.reasm);
		s->c_wnd.reasm = NULL;
		return 0;
	}

	return 1;
}

void _tcp_reasm_data(struct tcp_session *s, uint8_t to_server,
			uint32_t seq, uint32_t len, const uint8_t *buf)
{
	if ( NULL == s->app )
		return;
	do_data(s, to_server, seq, len, buf);
}

void _tcp_reasm_init(struct tcp_session *s, uint8_t to_server,
			uint32_t seq, uint32_t len, const uint8_t *buf)
{
	struct tcp_app *app;

	s->reasm_flags = 0;
	s->reasm_shutdown = 0;
	s->reasm_fin_sent = 0;

	app = _tcp_app_find_by_dport(s->s_port);
	if ( NULL == app || !app->a_init(s) )
		return;

	if ( !alloc_reasm_buffers(s) ) {
		app->a_fini(s);
		return;
	}

	dmesg(M_DEBUG, "allocated reasm buffers for %s", app->a_label);
	s->app = app;
	do_data(s, to_server, seq, len, buf);
}

static const char *tcp_chan_str(tcp_chan_t chan)
{
	switch(chan) {
	case TCP_CHAN_TO_SERVER:
		return "TO_SERVER";
	case TCP_CHAN_TO_CLIENT:
		return "TO_CLIENT";
	case TCP_CHAN_TO_SERVER|TCP_CHAN_TO_CLIENT:
		return "TO_SERVER|TO_CLIENT";
	case 0:
		return "NONE";
	default:
		return "FUCKED";
	}
}

static size_t contig_bytes(struct tcp_session *sesh, tcp_chan_t chan)
{
	struct tcp_state *s;
	uint32_t seq;

	assert(chan == TCP_CHAN_TO_CLIENT || chan == TCP_CHAN_TO_SERVER);

	if ( chan == TCP_CHAN_TO_CLIENT )
		s = sesh->s_wnd;
	else
		s = &sesh->c_wnd;

	if ( NULL == s->reasm )
		return 0;

	seq = s->snd_una;
	if ( chan & sesh->reasm_fin_sent && seq == s->snd_nxt )
		seq--;

	assert(!tcp_before(s->reasm->s_contig_seq, s->reasm->s_reasm_begin));
	if ( tcp_before(seq, s->reasm->s_reasm_begin) ) {
		mesg(M_CRIT, "wierd? %u %u", seq, s->reasm->s_reasm_begin);
		return 0;
	}

	if ( unlikely(tcp_after(seq, s->reasm->s_contig_seq)) ) {
		mesg(M_CRIT, "missing segment in %s stream %u-%u, %u rbufs",
			sesh->app->a_label, s->reasm->s_contig_seq,
			seq, s->reasm->s_num_rbuf);
		seq = s->reasm->s_contig_seq;
	}

	return tcp_diff(s->reasm->s_reasm_begin, seq);
}

static tcp_chan_t tcp_chan_data(struct tcp_session *s)
{
	tcp_chan_t ret = 0;

	ret |= (contig_bytes(s, TCP_CHAN_TO_SERVER)) ? TCP_CHAN_TO_SERVER : 0;
	ret |= (contig_bytes(s, TCP_CHAN_TO_CLIENT)) ? TCP_CHAN_TO_CLIENT : 0;

	return ret;
}

static const uint8_t *do_reasm(struct tcp_sbuf *s, size_t sz)
{
	static uint8_t *buf;
	static size_t buf_sz;
	struct tcp_rbuf *r;
	size_t left = sz;
	uint8_t *ptr;

	if ( 0 == sz )
		return NULL;

	/* FIXME: avoid buffer copy if buffer is contained in first rbuf */

	if ( tcp_after(s->s_reasm_begin + sz, s->s_contig_seq) )
		return NULL;

	if ( sz > buf_sz ) {
		uint8_t *new;

		new = realloc(buf, sz);
		dmesg(M_INFO, "tcp_stream: realloc to %u bytes %p", sz, new);
		if ( NULL == new )
			return NULL;

		buf = new;
		buf_sz = sz;
	}

	ptr = buf;

	list_for_each_entry(r, &s->s_bufs, r_list) {
		uint8_t *cp = r->r_base;
		size_t csz = RBUF_SIZE;

		if ( tcp_before(r->r_seq, s->s_reasm_begin) ) {
			cp += tcp_diff(r->r_seq, s->s_reasm_begin);
			csz -= tcp_diff(r->r_seq, s->s_reasm_begin);
		}

		if ( left < csz )
			csz = left;

		memcpy(ptr, cp, csz);
		ptr += csz;
		left -= csz;
		if ( 0 == left )
			break;
	}

	num_reasm++;
	return buf;
}

size_t tcp_sesh_get_bytes(tcp_sesh_t sesh, tcp_chan_t chan)
{
	return contig_bytes(sesh, chan);
}

static void munch_bytes(struct tcp_sbuf *s, size_t bytes)
{
	struct tcp_rbuf *buf, *tmp;
	uint32_t seq_end;

	seq_end = s->s_reasm_begin + bytes;
	assert(!tcp_after(seq_end, s->s_contig_seq));

	list_for_each_entry_safe(buf, tmp, &s->s_bufs, r_list) {
		uint32_t buf_end;

		buf_end = buf->r_seq + RBUF_SIZE;
		if ( tcp_after(seq_end, buf_end) ) {
			if ( buf == s->s_contig )
				s->s_contig = NULL;
			rbuf_free(s, buf);
		}else
			break;

	}

	s->s_reasm_begin = seq_end;
	if ( list_empty(&s->s_bufs) ) {
		dmesg(M_DEBUG, "re-basing from %u to %u",
			s->s_begin, s->s_reasm_begin);
		s->s_begin = s->s_reasm_begin;
	}else{
		buf = first_buffer(s);
		s->s_begin = buf->r_seq;
	}
	assert(!tcp_after(s->s_begin, s->s_reasm_begin));
}

static void *reasm_dcb;
static size_t reasm_dcb_sz;

size_t tcp_sesh_inject(tcp_sesh_t sesh, tcp_chan_t chan, size_t bytes)
{
	struct tcpstream_dcb *dcb;
	struct _pkt pkt;
	struct tcp_state *s;
	const uint8_t *buf;
	size_t total_bytes;

	if ( 0 == bytes )
		return 0;

	switch(chan) {
	case TCP_CHAN_TO_SERVER:
		s = &sesh->c_wnd;
		break;
	case TCP_CHAN_TO_CLIENT:
		s = sesh->s_wnd;
		break;
	default:
		mesg(M_WARN, "%s: attempted to get bad buf: %s",
			sesh->app->a_label, tcp_chan_str(chan));
		return bytes;
	}

again:
	total_bytes = contig_bytes(sesh, chan);
	assert(bytes <= total_bytes);
	buf = do_reasm(s->reasm, bytes);
	if ( NULL == buf )
		return 0;

	pkt.pkt_dcb = reasm_dcb;
	pkt.pkt_dcb_end = pkt.pkt_dcb + reasm_dcb_sz;
	pkt.pkt_dcb_top = pkt.pkt_dcb;
	dcb = (struct tcpstream_dcb *)decode_layerv(&pkt,
							&_p_tcpstream,
							sizeof(*dcb));
	assert(NULL != dcb);

	dcb->sesh = sesh;
	dcb->chan = chan;

	pkt.pkt_caplen = total_bytes;
	pkt.pkt_len = bytes;
	pkt.pkt_base = buf;
	pkt.pkt_end = buf + pkt.pkt_len;
	pkt.pkt_nxthdr = pkt.pkt_base;

	/* TODO: provide mechanism to detach protocols when encountering
	 * an invalid message. In the case of heuristically discovered
	 * protocols this will give us a chance to re-synchronize */
	dmesg(M_DEBUG, "tcp_reasm: %s: injecting %u/%u bytes",
		sesh->app->a_label, bytes, total_bytes);
	sesh->app->a_decode->d_decode(&pkt);
	if ( pkt.pkt_len > bytes ) {
		assert(pkt.pkt_caplen == total_bytes);
		if ( pkt.pkt_len <= total_bytes ) {
			dmesg(M_DEBUG, "tcp_reasm: trying again for %u bytes",
				pkt.pkt_len);
			bytes = pkt.pkt_len;
			goto again;
		}
		pkt.pkt_len = 0;
	}

	if ( pkt.pkt_len ) {
		dmesg(M_DEBUG, "tcp_reasm: injecting %u byte packet",
			pkt.pkt_len);
		munch_bytes(s->reasm, pkt.pkt_len);
		pkt_inject(&pkt);
		sesh->app->a_state_update(sesh, chan, &pkt);
	}

	return pkt.pkt_len;
}

static size_t fill_vectors(struct tcp_sbuf *s, size_t bytes,
			struct ro_vec *vec)
{
	struct tcp_rbuf *r;
	size_t i = 0;
	size_t left = bytes;

	list_for_each_entry(r, &s->s_bufs, r_list) {
		uint8_t *cp = r->r_base;
		size_t sz = RBUF_SIZE;

		if ( tcp_before(r->r_seq, s->s_reasm_begin) ) {
			cp += tcp_diff(r->r_seq, s->s_reasm_begin);
			sz -= tcp_diff(r->r_seq, s->s_reasm_begin);
		}

		if ( left < sz )
			sz = left;

		dmesg(M_DEBUG, " vec[%u] is %u bytes", i, sz);
		vec[i].v_ptr = cp;
		vec[i].v_len = sz;
		i++;
		left -= sz;
		if ( 0 == left )
			break;
	}

	return i;
}

static int assure_vbuf(struct tcp_sbuf *s, struct ro_vec **vec, size_t *numvec)
{
	struct tcp_rbuf *r;
	struct ro_vec *new;
	size_t n;

	r = first_buffer(s);
	n = tcp_diff(r->r_seq, s->s_contig->r_seq + RBUF_SIZE) / RBUF_SIZE;
	dmesg(M_DEBUG, "assuring %u vectors", n);

	if ( *numvec >= n )
		return 1;

	new = realloc(*vec, sizeof(*new) * n);
	if ( NULL == new )
		return 0;

	*vec = new;
	*numvec = n;
	return 1;
}

const struct ro_vec *tcp_sesh_get_buf(tcp_sesh_t sesh, tcp_chan_t chan,
				size_t *numv, size_t *bytes)
{
	static struct ro_vec *vbuf;
	static size_t vbuf_sz;
	struct tcp_state *s;
	struct ro_vec *vec;
	size_t n, b;

	switch(chan) {
	case TCP_CHAN_TO_SERVER:
		s = &sesh->c_wnd;
		break;
	case TCP_CHAN_TO_CLIENT:
		s = sesh->s_wnd;
		break;
	default:
		mesg(M_WARN, "%s: attempted to get bad buf: %s",
			sesh->app->a_label, tcp_chan_str(chan));
		return NULL;
	}

	assert(NULL != s);

	/* fuck me, this is clever */
	if ( !assure_vbuf(s->reasm, &vbuf, &vbuf_sz) )
		return NULL;

	b = contig_bytes(sesh, chan);
	if ( 0 == b )
		return NULL;

	vec = vbuf;
	n = fill_vectors(s->reasm, b, vec);
	dmesg(M_DEBUG, "tcp_reasm(%s): alloc %u bytes in %u vectors",
			tcp_chan_str(chan), b, n);

	*numv = n;
	*bytes = b;
	return vec;
}

static void do_push(struct tcp_session *s, tcp_chan_t chan)
{
	tcp_chan_t achan;
	int ret;

	achan = tcp_chan_data(s);

	dmesg(M_ERR, "stream_push: %s", tcp_chan_str(chan));
	dmesg(M_ERR, "available chans: %s", tcp_chan_str(achan));

	for(; achan & s->reasm_flags; achan = tcp_chan_data(s) ) {
		dmesg(M_ERR, "%s_push: %s waiting for %s", s->app->a_label,
			tcp_chan_str(achan), tcp_chan_str(s->reasm_flags));
		ret = s->app->a_push(s, achan);
		if ( ret < 0 )
			mesg(M_CRIT, "%s: desynchronised", s->app->a_label);
		if ( ret <= 0 )
			break;
	}
}

void _tcp_reasm_ack(struct tcp_session *s, uint8_t to_server)
{
	if ( NULL == s->app )
		return;

	do_push(s, (to_server) ?
			TCP_CHAN_TO_SERVER : TCP_CHAN_TO_CLIENT);
}

void _tcp_reasm_abort(struct tcp_session *s, int rst)
{
	if ( NULL == s->app )	
		return;
	do_abort(s, rst);
}

size_t _tcp_reasm_buffer_size(struct tcp_session *s)
{
	size_t ret = 0;

	if ( NULL == s->app )
		return ret;

	if ( s->c_wnd.reasm )
		ret += s->c_wnd.reasm->s_num_rbuf << RBUF_SHIFT;
	if ( s->s_wnd && s->s_wnd->reasm )
		ret += s->s_wnd->reasm->s_num_rbuf << RBUF_SHIFT;

	return ret;
}

void _tcp_reasm_fin_sent(struct tcp_session *s, uint8_t to_server)
{
	tcp_chan_t chan;
	chan = (to_server) ? TCP_CHAN_TO_SERVER : TCP_CHAN_TO_CLIENT;
	s->reasm_fin_sent |= chan;
}

static void do_shutdown(struct tcp_session *s, tcp_chan_t chan)
{
	struct tcp_sbuf **pptr;
	size_t bytes;

	switch(chan) {
	case TCP_CHAN_TO_SERVER:
		pptr = &s->c_wnd.reasm;
		break;
	case TCP_CHAN_TO_CLIENT:
		pptr = &s->s_wnd->reasm;
		break;
	default:
		assert(0);
		break;
	}

	bytes = contig_bytes(s, chan);
	if ( bytes ) {
		const uint8_t *buf;
		mesg(M_WARN, "%s: TO_CLIENT %u bytes left on shutdown",
			s->app->a_label, bytes);
		buf = do_reasm(*pptr, bytes);
		if ( NULL != buf )
			hex_dump(buf, (bytes > 0x100) ? 0x100 : bytes, 16);
	}


	sbuf_free(s, *pptr);
	*pptr = NULL;
}
void _tcp_reasm_shutdown(struct tcp_session *s, uint8_t to_server)
{
	tcp_chan_t chan;

	if ( NULL == s->app )
		return;

	chan = (to_server) ? TCP_CHAN_TO_SERVER : TCP_CHAN_TO_CLIENT;

	do_push(s, tcp_chan_data(s));

	s->reasm_shutdown |= chan;

	dmesg(M_ERR, "stream_shutdown: %s", tcp_chan_str(chan));
	s->app->a_shutdown(s, chan);

	do_shutdown(s, (to_server) ? TCP_CHAN_TO_SERVER : TCP_CHAN_TO_CLIENT);

	if ( s->reasm_shutdown & (TCP_CHAN_TO_SERVER|TCP_CHAN_TO_CLIENT) ) {
		s->app->a_fini(s);
		s->app = NULL;
		s->flow = NULL;
	}
}


void tcp_sesh_set_flow(tcp_sesh_t sesh, void *flow)
{
	sesh->flow = flow;
}

void *tcp_sesh_get_flow(tcp_sesh_t sesh)
{
	return sesh->flow;
}

void tcp_sesh_wait(tcp_sesh_t sesh, tcp_chan_t chan)
{
	if ( chan & sesh->reasm_shutdown ) {
		mesg(M_WARN, "%s: attempted to wait on shutdown chan: %s",
			sesh->app->a_label,
			tcp_chan_str(chan & sesh->reasm_shutdown));
		asm volatile ("int $0x3\n");
		chan &= ~sesh->reasm_shutdown;
	}

	sesh->reasm_flags = chan;
}

int _tcp_reasm_ctor(mempool_t pool)
{
	sbuf_cache = objcache_init(pool, "tcp_sbuf", sizeof(struct tcp_sbuf));
	if ( sbuf_cache == NULL )
		return 0;

	rbuf_cache = objcache_init(pool, "tcp_rbuf", sizeof(struct tcp_rbuf));
	if ( rbuf_cache == NULL )
		return 0;

	data_cache = objcache_init(pool, "tcp_data", RBUF_SIZE);
	if ( data_cache == NULL )
		return 0;

	gap_cache = objcache_init(pool, "tcp_gap", sizeof(struct tcp_gap));
	if ( gap_cache == NULL )
		return 0;

	reasm_dcb_sz = _tcp_app_max_dcb();
	reasm_dcb = malloc(reasm_dcb_sz);
	if ( NULL == reasm_dcb )
		return 0;

	return 1;
}

void _tcp_reasm_dtor(void)
{
	unsigned int avg;

	avg = push_bytes / ((num_push) ? num_push : 1);

	mesg(M_INFO, "tcp_reasm: reasm=%u push=%u avg_bytes=%u max_gaps=%u",
		num_reasm, num_push, avg, max_gaps);

	free(reasm_dcb);
}
