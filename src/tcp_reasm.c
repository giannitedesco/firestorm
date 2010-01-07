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
#include <f_stream.h>
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

int _tcp_reasm_inject(struct tcp_session *s, unsigned int chan,
			uint32_t seq, uint32_t len, const uint8_t *buf)
{
	switch(chan) {
	case TCP_CHAN_TO_SERVER:
		return do_inject(s, s->c_wnd.reasm, seq, len, buf);
	case TCP_CHAN_TO_CLIENT:
		return do_inject(s, s->s_wnd->reasm, seq, len, buf);
	default:
		assert(0);
		break;
	}
	return 0;
}

static void sbuf_free(struct tcp_session *ss, struct tcp_sbuf *s, int abort)
{
	struct tcp_rbuf *r, *tr;
	unsigned int i;

	if ( NULL == s )
		return;

	if ( !abort )
		if (s->s_reasm_begin != s->s_end) {
			mesg(M_DEBUG, "whoah %u bytes left %u gaps (%s)",
				tcp_diff(s->s_reasm_begin, s->s_end),
				s->s_num_gaps, ss->proto->sd_label);
		}

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

static void final_push(struct tcp_session *s);
void _tcp_reasm_free(struct tcp_session *s, int abort)
{
	if ( NULL == s )
		return;

	if ( !abort )
		final_push(s);

	sbuf_free(s, s->c_wnd.reasm, abort);
	if ( s->s_wnd )
		sbuf_free(s, s->s_wnd->reasm, abort);
}

int _tcp_reasm_init(struct tcp_session *s)
{
	s->c_wnd.reasm = sbuf_new(s, s->c_wnd.snd_nxt);
	if ( NULL == s->c_wnd.reasm )
		return 0;

	s->s_wnd->reasm = sbuf_new(s, s->s_wnd->snd_nxt);
	if ( NULL == s->s_wnd->reasm ) {
		sbuf_free(s, s->c_wnd.reasm, 1);
		s->c_wnd.reasm = NULL;
		return 0;
	}

	return 1;
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

static struct ro_vec *advance_reasm_begin(struct tcp_sbuf *s,
						struct ro_vec *vec,
						size_t *numv,
						size_t bytes)
{
	size_t i, n = *numv;

	s->s_reasm_begin += bytes;

	for(i = 0; i < n; i++, vec++, (*numv)--) {
		struct tcp_rbuf *r = first_buffer(s);

		s->s_begin = r->r_seq;

		if ( bytes < vec->v_len ) {
			vec->v_len -= bytes;
			vec->v_ptr += bytes;
			break;
		}

		if ( vec->v_ptr + vec->v_len == r->r_base + RBUF_SIZE ) {
			rbuf_free(s, r);
			if ( s->s_contig == r )
				s->s_contig = NULL;
		}

		assert(bytes >= vec->v_len);
		bytes -= vec->v_len;
	}

	return vec;

}

void _tcpstream_decode(struct _pkt *pkt)
{
	mesg(M_DEBUG, "_tcpstream_decode()");
}

static struct _pkt reasm_pkt;
static ssize_t stream_push(struct tcp_session *ss,
				unsigned int chan, uint32_t seq)
{
	static struct ro_vec *vbuf;
	static size_t vbuf_sz;
	struct tcpstream_dcb *dcb;
	struct tcp_sbuf *s;
	size_t sz, numv;
	struct ro_vec *vec;
	ssize_t rret;
	char *str;

	switch(chan) {
	case TCP_CHAN_TO_SERVER:
		str = "to_server";
		s = ss->c_wnd.reasm;
		break;
	case TCP_CHAN_TO_CLIENT:
		str = "to_client";
		if ( NULL == ss->s_wnd )
			return 0;
		s = ss->s_wnd->reasm;
		break;
	default:
		return 1;
	}

	assert(!tcp_before(s->s_reasm_begin, s->s_begin));
	if ( !tcp_after(seq, s->s_reasm_begin) )
		return 0;
	if ( unlikely(tcp_after(seq, s->s_contig_seq)) ) {
		dmesg(M_CRIT, "missing segment in %s stream %u-%u, %u rbufs",
			ss->proto->sd_label, s->s_contig_seq,
			seq, s->s_num_rbuf);
		seq = s->s_contig_seq;
	}
	sz = tcp_diff(s->s_reasm_begin, seq);
	if ( 0 == sz )
		return 0;
	assert(s->s_contig);

	if ( !assure_vbuf(s, &vbuf, &vbuf_sz) )
		return -1;
	vec = vbuf;
	numv = fill_vectors(s, sz, vec);
	dmesg(M_DEBUG, "tcp_reasm(%s): alloc %u bytes in %u vectors",
			str, sz, numv);

	reasm_pkt.pkt_ts = 0; /* FIXME */

	for(rret = 0; sz; rret++) {
		ssize_t ret;

		reasm_pkt.pkt_dcb_top = reasm_pkt.pkt_dcb;
		dcb = (struct tcpstream_dcb *)decode_layerv(&reasm_pkt,
								NULL,
								sizeof(*dcb));
		if ( NULL == dcb )
			break;

		dcb->s = ss;
		dcb->sbuf = s;
		dcb->reasm = do_reasm;
		dcb->chan = chan;

		/* to be populated by stream push */
		reasm_pkt.pkt_caplen = 0;
		reasm_pkt.pkt_len = 0;
		reasm_pkt.pkt_base = NULL;
		reasm_pkt.pkt_end = NULL;
		reasm_pkt.pkt_nxthdr = NULL;

		ret = ss->proto->sd_push(&reasm_pkt, vec, numv, sz);
		dmesg(M_DEBUG, " sd_push: %i/%u bytes taken", ret, sz);
		if ( ret < 0 ) {
			mesg(M_CRIT, "tcp_reasm(%s): %s: desynchronised",
				str, ss->proto->sd_label);
			return -1;
		}
		if ( ret == 0)
			break;

		assert((size_t)ret <= sz);

		sz -= (size_t)ret;
		vec = advance_reasm_begin(s, vec, &numv, ret);

		num_push++;
		push_bytes += ret;
	}

	if ( s->s_begin == s->s_end ) {
		assert(list_empty(&s->s_bufs));
		assert(s->s_end == s->s_contig_seq);
		assert(s->s_reasm_begin == s->s_contig_seq);
		s->s_begin = s->s_contig_seq;
		if ( ss->proto->sd_stream_clear )
			ss->proto->sd_stream_clear(&dcb->dcb);
	}

	assert(!tcp_before(s->s_contig_seq, s->s_begin));
	assert(!tcp_before(s->s_contig_seq, s->s_reasm_begin));

	return rret;
}

static uint32_t spec_ack(struct tcp_state *wnd)
{
	if ( NULL == wnd->reasm->s_contig )
		return wnd->reasm->s_reasm_begin;
	if ( tcp_after(wnd->snd_una, wnd->reasm->s_contig_seq) )
		return wnd->reasm->s_contig_seq;
	return wnd->snd_una;
}

static int do_push(struct tcp_session *ss, schan_t chan,
			uint32_t c_seq, uint32_t s_seq)
{
	int tries;
	uint32_t seq[] = {
		[TCP_CHAN_TO_SERVER] = c_seq,
		[TCP_CHAN_TO_CLIENT] = s_seq,
	};

	if ( unlikely(NULL == reasm_pkt.pkt_dcb) ) {
		if ( !decode_pkt_realloc(&reasm_pkt,
					DECODE_DEFAULT_MIN_LAYERS) )
			return 0;
	}

	for(tries = 0; tries < 2; chan ^= 1 ) {
		int ret;

		ret = stream_push(ss, chan, seq[chan]);
		if ( ret < -1 )
			return 0;
		if ( 0 == ret ) 
			tries++;
		else
			tries = 0;
	}
	return 1;
}

int _tcp_stream_push(struct tcp_session *s, unsigned int chan, uint32_t ack)
{
	switch(chan) {
	case TCP_CHAN_TO_SERVER:
		return do_push(s, chan, ack, spec_ack(s->s_wnd));
	case TCP_CHAN_TO_CLIENT:
		return do_push(s, chan, spec_ack(&s->c_wnd), ack);
	default:
		return 1;
	}
}

static void final_push(struct tcp_session *s)
{
	uint32_t c_seq, s_seq;

	if ( NULL == s->c_wnd.reasm || NULL == s->proto )
		return;
	c_seq = spec_ack(&s->c_wnd);
	s_seq = (s->s_wnd && s->s_wnd->reasm) ? spec_ack(s->s_wnd) : 0;

	/* arbitrary choice of first chan to try */
	mesg(M_DEBUG, "final push (%s)", s->proto->sd_label);
	do_push(s, TCP_CHAN_TO_SERVER, c_seq, s_seq);
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

	return 1;
}

void _tcp_reasm_dtor(void)
{
	unsigned int avg;

	avg = push_bytes / ((num_push) ? num_push : 1);

	mesg(M_INFO, "tcp_reasm: reasm=%u push=%u avg_bytes=%u max_gaps=%u",
		num_reasm, num_push, avg, max_gaps);
}
