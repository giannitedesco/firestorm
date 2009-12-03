/* Copyright (c) Gianni Tedesco 2009
 * Author: Gianni Tedesco (gianni at scaramanga dot co dot uk)
 *
 * This is a fast tcp stream reassembly module which manages allocation of
 * contiguous chunks of memory (say 2 to the power of 7-9 bytes).
*/
#include <firestorm.h>
#include <pkt/tcp.h>
#include <list.h>
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
	dmesg(M_DEBUG, "Swallow gap %u %u-%u\n", i,
		s->s_gap[i]->g_begin, s->s_gap[i]->g_end);
	gap_free(s->s_gap[i]);
	for(--s->s_num_gaps; i < s->s_num_gaps; i++) {
		dmesg(M_DEBUG, " Shuffle gap %u to %u\n", i + 1, i);
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
		dmesg(M_DEBUG, " new contig_seq: %u -> %u\n",
			s->s_contig_seq, g->g_begin);
		s->s_contig_seq = g->g_begin;
	}else{
		dmesg(M_DEBUG, " new contig_seq: %u -> %u (buffer contig)\n",
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
	dmesg(M_DEBUG, "Appending gap %u-%u\n", s->s_end, seq);
	if (s->s_num_gaps >= TCP_REASM_MAX_GAPS)
		return 0;
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

	if (s->s_num_gaps >= TCP_REASM_MAX_GAPS)
		return 0;

	dmesg(M_DEBUG, "Split gap\n");
	for(n = i + 1, j = s->s_num_gaps; j > n; --j) {
		dmesg(M_DEBUG, " Shuffle gap %d to %d\n", j - 1, j);
		s->s_gap[j] = s->s_gap[j - 1];
	}

	dmesg(M_DEBUG, " gap %d-%u: %u-%u -> (%u-%u, %u-%u)\n", i, n,
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

			dmesg(M_DEBUG, "Backward overlap\n");
			dmesg(M_DEBUG, " %u-%u -> %u-%u\n",
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

			dmesg(M_DEBUG, "Forward overlap\n");
			dmesg(M_DEBUG, " %u-%u -> %u-%u\n",
				g->g_begin, g->g_end,
				seq_end, g->g_end);
			g->g_begin = seq_end;
		}
	}
	return 1;
}

/* input packet data in to the reassembly system */
int _tcp_reasm_inject(struct tcp_session *ss, struct tcp_sbuf *s,
			uint32_t seq, uint32_t len, const uint8_t *buf)
{
	uint32_t seq_end = seq + len;
	uint32_t base, ofs, clen, sseq;
	int is_contig;
	struct tcp_rbuf *r, *lr;

	dmesg(M_DEBUG, "Inject Packet: %u - %u : '%.*s'\n",
		seq, seq + len, len, buf);

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

	dmesg(M_DEBUG, " Trimmed data: %u - %u : '%.*s'\n",
		seq, seq + len, len, buf);

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
	dmesg(M_DEBUG, "Copying data to buffers:\n");
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
			dmesg(M_DEBUG, " ... and put it after %u\n", r->r_seq);
			list_add(&nr->r_list, &r->r_list);
			r = nr;
		}else if ( tcp_before(base, r->r_seq) ) {
			nr = rbuf_alloc(ss, s, base);
			if ( NULL == nr )
				return 0;
			dmesg(M_DEBUG, " ... and put it before %u\n", r->r_seq);
			list_add_tail(&nr->r_list, &r->r_list);
			r = nr;
		}

		dmesg(M_DEBUG, " Copy data: base=%u:%u ofs=%u len=%u : '%.*s'\n",
			r->r_seq, base, ofs, clen, clen, buf);
		assert(r->r_seq == base);

		memcpy(r->r_base + ofs, buf, clen);
		lr = r;

		sseq += clen;
		buf += clen;
		len -= clen;

		if ( is_contig )
			s->s_contig = r;

		assert(!tcp_after(sseq, seq_end));
	}

	if ( tcp_after(seq_end, s->s_end) ) {
		dmesg(M_DEBUG, " Setting seq_end to %u\n", seq_end);
		s->s_end = seq_end;
	}
	return 1;
}

void _tcp_reasm_free(struct tcp_sbuf *s)
{
	struct tcp_rbuf *r, *tr;
	unsigned int i;

	if ( s->s_bufs.prev ) {
		list_for_each_entry_safe(r, tr, &s->s_bufs, r_list) {
			rbuf_free(s, r);
		}
	}

	for(i = 0; i < s->s_num_gaps; i++)
		gap_free(s->s_gap[i]);

	s->s_num_gaps = 0;
}

void _tcp_reasm_init(struct tcp_sbuf *s, uint32_t isn)
{
	memset(s, 0, sizeof(*s));
	INIT_LIST_HEAD(&s->s_bufs);
	s->s_begin = isn;
	s->s_reasm_begin = isn;
	s->s_end = isn;
	s->s_contig_seq = isn;
}

static size_t do_reasm(struct _stream *ss, uint8_t *buf, size_t sz)
{
	struct tcp_stream *st = (struct tcp_stream *)ss;
	struct tcp_sbuf *s = st->sbuf;
	struct tcp_rbuf *r;
	size_t left = sz;

	if ( NULL == buf || 0 == sz )
		return 0;
	if ( tcp_after(s->s_reasm_begin + sz, s->s_contig_seq) )
		return 0;

	list_for_each_entry(r, &s->s_bufs, r_list) {
		uint8_t *cp = r->r_base;
		size_t csz = RBUF_SIZE;

		if ( tcp_before(r->r_seq, s->s_reasm_begin) ) {
			cp += tcp_diff(r->r_seq, s->s_reasm_begin);
			csz -= tcp_diff(r->r_seq, s->s_reasm_begin);
		}

		if ( left < csz )
			csz = left;

		memcpy(buf, cp, csz);
		buf += csz;
		left -= csz;
		if ( 0 == left )
			break;
	}

	num_reasm++;
	return sz;
}

static size_t fill_vectors(struct tcp_sbuf *s, size_t bytes,
			struct ro_vec *vec, size_t numv)
{
	struct tcp_rbuf *r;
	size_t i = 0, ret = 0;
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
		assert(i < numv);
		vec[i].v_ptr = cp;
		vec[i].v_len = sz;
		i++;
		left -= sz;
		ret += sz;
		if ( 0 == left )
			break;
	}

	return ret;
}

static size_t num_vectors(struct tcp_sbuf *s, size_t bytes)
{
	struct tcp_rbuf *r;
	size_t left = bytes;
	size_t cnt = 0;

	list_for_each_entry(r, &s->s_bufs, r_list) {
		size_t sz = RBUF_SIZE;
		if ( tcp_before(r->r_seq, s->s_reasm_begin) )
			sz -= tcp_diff(r->r_seq, s->s_reasm_begin);
		if ( left < sz )
			sz = left;
		left -= sz;
		cnt++;
		if ( 0 == left )
			break;
	}

	return cnt;
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

		if ( bytes < vec->v_len ) {
			vec->v_len -= bytes;
			vec->v_ptr += bytes;
			break;
		}

		s->s_begin = r->r_seq;
		if ( vec->v_ptr + vec->v_len == r->r_base + RBUF_SIZE )
			rbuf_free(s, r);
		if ( s->s_contig == r )
			s->s_contig = NULL;

		bytes -= vec->v_len;
	}

	return vec;

}

int _tcp_stream_push(struct tcp_session *ss, struct tcp_sbuf *s, uint32_t seq)
{
	struct tcp_stream stream;
	unsigned int chan;
	size_t sz, sz2, numv;
	struct ro_vec *vec, *vbuf;
	char *str;

	if ( s == &ss->c_wnd.reasm) {
		chan = TCP_CHAN_TO_SERVER;
		str = "to_server";
	}else{
		chan = TCP_CHAN_TO_CLIENT;
		str = "to_client";
	}

	assert(!tcp_before(s->s_reasm_begin, s->s_begin));
	if ( !tcp_after(seq, s->s_reasm_begin) )
		return 1;
	if ( unlikely(tcp_after(seq, s->s_contig_seq)) ) {
		dmesg(M_CRIT, "missing segment in tcp stream %u-%u",
			s->s_contig_seq, seq);
		return 1;
	}

	sz = tcp_diff(s->s_reasm_begin, seq);

	numv = num_vectors(s, sz);
	vbuf = vec = calloc(numv, sizeof(*vec));
	if ( NULL == vec )
		return 1;

	dmesg(M_DEBUG, "tcp_reasm(%s): alloc %u bytes in %u vectors",
			str, sz, numv);

	sz2 = fill_vectors(s, sz, vec, numv);
	dmesg(M_DEBUG, " %u bytes filled", sz2);
	assert(sz == sz2);

	stream.stream.s_reasm = do_reasm;
	stream.stream.s_flow = ss->flow;
	stream.s = ss;
	stream.sbuf = s;

	while(sz) {
		ssize_t ret;
		ret = ss->proto->sp_push(&stream.stream, chan, vec, numv, sz);
		dmesg(M_DEBUG, " sp_push: %i/%u bytes taken", ret, sz);
		if ( ret < 0 ) {
			dmesg(M_CRIT, "tcp_reasm(%s): desynchronised", str);
			return 0;
		}
		if ( ret == 0)
			break;

		assert((size_t)ret <= sz);
		sz -= (size_t)ret;
		vec = advance_reasm_begin(s, vec, &numv, ret);

		num_push++;
		push_bytes += ret;
	}

	if ( list_empty(&s->s_bufs) ) {
		assert(s->s_end == s->s_contig_seq);
		assert(s->s_reasm_begin == s->s_contig_seq);
		s->s_begin = s->s_contig_seq;
	}

	assert(!tcp_before(s->s_contig_seq, s->s_begin));
	assert(!tcp_before(s->s_contig_seq, s->s_reasm_begin));

	free(vbuf);
	return 1;
}

int _tcp_reasm_ctor(mempool_t pool)
{
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

#if 0
static void print_gap(uint32_t len)
{
	dmesg(M_DEBUG, "\033[31m");
	while (len--)
		dmesg(M_DEBUG, "#");
	dmesg(M_DEBUG, "\033[0m");
}
static void stream_print(struct tcp_sbuf *s)
{
	struct tcp_rbuf *r;
	struct tcp_gap *n;
	unsigned int i;

	dmesg(M_DEBUG, "Stream begins at %u\n", s->s_begin);
	if ( s->s_contig ) {
		dmesg(M_DEBUG, " contig = %u - %u\n",
			s->s_contig->r_seq,
			s->s_contig_seq);
	}

	dmesg(M_DEBUG, " data: '");
	list_for_each_entry(r, &s->s_bufs, r_list) {
		if ( tcp_before(s->s_contig_seq, r->r_seq + RBUF_SIZE) ) {
			dmesg(M_DEBUG, "%.*s",
				seq_ofs(s, s->s_contig_seq), r->r_base);
			break;
		}
		dmesg(M_DEBUG, "%.*s", RBUF_SIZE, r->r_base);
	}

	for(i = 0; i < s->s_num_gaps; ++i) {
		uint32_t buf_end;
		uint32_t nxt;

		n = s->s_gap[i];
		if ( i + 1 == s->s_num_gaps )
			nxt = s->s_end;
		else
			nxt = s->s_gap[i + 1]->g_begin;
		print_gap(gap_len(n));

		for(; r; r = rbuf_next(s, r)) {
			uint8_t *begin, *end;

			begin = r->r_base;
			end = r->r_base + RBUF_SIZE;
			buf_end = r->r_seq + RBUF_SIZE;
			//dmesg(M_DEBUG, "\033[33m%u:%u:%u:%u\033[0m",
			//	r->r_seq, n->g_begin, n->g_end, nxt);

			if ( !tcp_after(buf_end, n->g_end) )
				continue;

			if ( tcp_before(r->r_seq, n->g_end ) ) {
				begin += tcp_diff(r->r_seq, n->g_end);
			}
			if ( tcp_after(buf_end, nxt) ) {
				end -= tcp_diff(nxt, buf_end);
			}

			assert(end >= begin);
			assert((end - begin) <= RBUF_SIZE);
			dmesg(M_DEBUG, "\033[32m%.*s\033[0m", end - begin, begin);
			if ( !tcp_before(buf_end, nxt) )
				break;
		}
	}

	dmesg(M_DEBUG, "'\n\n");
}

#define PKT_OFS 0xfffffff0
static int stream_check(struct tcp_sbuf *s, const char *buf, size_t sz)
{
	struct tcp_rbuf *r;
	char tmp[sz];
	char *ptr = tmp;

	if ( s->s_contig_seq != s->s_end )
		return 0;

	list_for_each_entry(r, &s->s_bufs, r_list) {
		if ( tcp_before(s->s_contig_seq, r->r_seq + RBUF_SIZE) ) {
			ptr += sprintf(ptr, "%.*s",
				seq_ofs(s, s->s_contig_seq), r->r_base);
			break;
		}
		ptr += sprintf(ptr, "%.*s", RBUF_SIZE, r->r_base);
	}
	return !memcmp(tmp, buf, sz);
}

static void reseed_random(void)
{
	unsigned int seed;
	FILE *f;

#if 1
	f = fopen("/dev/urandom", "r");
	fread(&seed, sizeof(seed), 1, f);
	fclose(f);
#else
	seed = 1906306429;
#endif
	dmesg(M_DEBUG, "Random seed: %u\n", seed);
	srand(seed);
}

static void test_random(const char *buf, size_t sz)
{
	uint32_t seq_end = PKT_OFS + sz;
	struct tcp_sbuf s;

	reseed_random();

	_tcp_reasm_init(&s, PKT_OFS);

	sz++;

	while(s.s_contig_seq != seq_end) {
		uint32_t ofs, len;

		ofs = rand() % sz;
		len = rand() % (sz - ofs);

		_tcp_reasm_inject(&s, PKT_OFS + ofs, len, buf + ofs);
		stream_print(&s);
	}

	assert(stream_check(&s, buf, sz));

	_tcp_reasm_free(&s);
}

static void test_contig(const char *buf, size_t sz, size_t csz)
{
	uint32_t seq = PKT_OFS;
	struct tcp_sbuf s;

	_tcp_reasm_init(&s, seq);
	while(sz) {
		if ( csz > sz )
			csz = sz;
		_tcp_reasm_inject(&s, seq, csz, buf);
		stream_print(&s);
		buf += csz;
		seq += csz;
		sz -= csz;
	}
	_tcp_reasm_free(&s);
}

int main(int argc, char **argv)
{
	dmesg(M_DEBUG, "TCP Reassembly Test Rig.\n"
		"========================\n"
		"%u byte buffers, rbuf = %u bytes\n"
		"stream = %u bytes, gap = %u bytes\n\n",
		RBUF_SIZE, sizeof(struct tcp_rbuf),
		sizeof(struct tcp_sbuf), sizeof(struct tcp_gap));

	//test_contig("Hello world! How are You? I am fine.", 36, 3);
	test_random("Hello world! How are You? I am fine.", 36);

	return 0;
}
#endif
