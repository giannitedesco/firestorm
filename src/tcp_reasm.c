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
#define dprintf printf
#else
#define dprintf(x...) do { } while(0);
#endif

#define RBUF_SHIFT	7
#define RBUF_SIZE	(1<<RBUF_SHIFT)
#define RBUF_MASK	(RBUF_SIZE - 1)
#define RBUF_BASE	(~RBUF_MASK)

static uint32_t seq_base(struct tcp_sbuf *s, uint32_t seq)
{
	return s->s_begin + (tcp_diff(s->s_begin, seq) & RBUF_BASE);
}

static uint32_t seq_ofs(struct tcp_sbuf *s, uint32_t seq)
{
	return tcp_diff(s->s_begin, seq) & RBUF_MASK;
}

/* Node allocation
 * TODO: ditch malloc for a preallocated stack + eviction
 */
static struct tcp_gap *gap_alloc(void)
{
	struct tcp_gap *ret;
	ret = calloc(1, sizeof(*ret));
	return ret;
}

static void gap_free(struct tcp_gap *n)
{
	free(n);
}

static inline uint32_t gap_len(struct tcp_gap *g)
{
	assert(tcp_after(g->g_end, g->g_begin));
	return tcp_diff(g->g_begin, g->g_end);
}

static struct tcp_rbuf *rbuf_alloc(struct tcp_sbuf *s, uint32_t seq)
{
	struct tcp_rbuf *r;
	assert(((seq - s->s_begin) & RBUF_MASK) == 0);
	r = calloc(1, sizeof(*r) + RBUF_SIZE);
	if ( r ) {
		INIT_LIST_HEAD(&r->r_list);
		r->r_seq = seq;
		r->r_base = (uint8_t *)&r[1];
		memset(r->r_base, '#', RBUF_SIZE);
		dprintf(" Allocated rbuf seq=%u\n", seq);
	}
	return r;
}

static void rbuf_free(struct tcp_rbuf *r)
{
	list_del(&r->r_list);
	free(r);
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
static struct tcp_gap *gap_new(uint32_t begin, uint32_t end)
{
	struct tcp_gap *n;

	assert(!tcp_after(begin, end));

	n = gap_alloc();
	if ( NULL != n ) {
		n->g_begin = begin;
		n->g_end = end;
	}

	return n;
}

static struct tcp_rbuf *first_buffer(struct tcp_sbuf *s)
{
	if ( list_empty(&s->s_bufs) )
		return NULL;
	return list_entry(s->s_bufs.next, struct tcp_rbuf, r_list);
}

static struct tcp_rbuf *find_buf_fwd(struct tcp_sbuf *s, struct tcp_rbuf *r,
					uint32_t seq)
{
	struct tcp_rbuf *new;

	for(; r; r = rbuf_next(s, r)) {
		if ( r->r_seq == seq )
			break;
		if ( tcp_after(r->r_seq, seq) ) {
			new = rbuf_alloc(s, seq);
			list_add_tail(&new->r_list, &r->r_list);
			r = new;
			break;
		}
	}

	if ( NULL == r ) {
		new = rbuf_alloc(s, seq);
		list_add_tail(&new->r_list, &s->s_bufs);
		r = new;
	}

	return r;
}

static struct tcp_rbuf *contig_buf(struct tcp_sbuf *s, uint32_t seq)
{
	struct tcp_rbuf *r;

	r = (s->s_contig) ? s->s_contig : first_buffer(s);
	return find_buf_fwd(s, r, seq);
}

static struct tcp_rbuf *discontig_buf(struct tcp_sbuf *s, uint32_t seq)
{
	struct tcp_rbuf *r;
	r = find_buf_fwd(s, first_buffer(s), seq);
	return r;
}

static void swallow_gap(struct tcp_sbuf *s, unsigned int i)
{
	dprintf("Swallow gap %u %u-%u\n", i,
		s->s_gap[i]->g_begin, s->s_gap[i]->g_end);
	gap_free(s->s_gap[i]);
	for(--s->s_num_gaps; i < s->s_num_gaps; i++) {
		dprintf(" Shuffle gap %u to %u\n", i + 1, i);
		s->s_gap[i] = s->s_gap[i + 1];
	}
}

static void contig_eat_gaps(struct tcp_sbuf *s, uint32_t seq_end)
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
		dprintf(" new contig_seq: %u -> %u\n",
			s->s_contig_seq, g->g_begin);
		s->s_contig_seq = g->g_begin;
	}else{
		dprintf(" new contig_seq: %u -> %u (buffer contig)\n",
			s->s_contig_seq, seq_end);
		if ( tcp_after(seq_end, s->s_end) )
			s->s_contig_seq = seq_end;
		else
			s->s_contig_seq = s->s_end;
	}
}

static void append_gap(struct tcp_sbuf *s, struct tcp_rbuf *r,
			uint32_t seq, uint32_t seq_end)
{
	dprintf("Appending gap %u-%u\n", s->s_end, seq);
	assert(s->s_num_gaps <= TCP_REASM_MAX_GAPS);
	s->s_gap[s->s_num_gaps] = gap_new(s->s_end, seq);
	s->s_num_gaps++;
}

static void split_gap(struct tcp_sbuf *s, int i, struct tcp_rbuf *r,
			uint32_t seq, uint32_t seq_end)
{
	int n, j;

	assert(s->s_num_gaps <= TCP_REASM_MAX_GAPS);

	dprintf("Split gap\n");
	for(n = i + 1, j = s->s_num_gaps; j > n; --j) {
		dprintf(" Shuffle gap %d to %d\n", j - 1, j);
		s->s_gap[j] = s->s_gap[j - 1];
	}

	dprintf(" gap %d-%u: %u-%u -> (%u-%u, %u-%u)\n", i, n,
		s->s_gap[i]->g_begin, s->s_gap[i]->g_end,
		s->s_gap[i]->g_begin, seq,
		seq_end, s->s_gap[i]->g_end);

	s->s_gap[n] = gap_new(seq_end, s->s_gap[i]->g_end);
	s->s_gap[i]->g_end = seq;
	s->s_num_gaps++;
}

static void frob_gaps(struct tcp_sbuf *s, struct tcp_rbuf *r,
			uint32_t seq, uint32_t seq_end)
{
	unsigned int i;

	for(i = 0; i < s->s_num_gaps; i++) {
		struct tcp_gap *g = s->s_gap[i];
		if ( tcp_after(seq, g->g_begin) ) {
			if ( tcp_after(seq, g->g_end) )
				continue;

			/* There can be...only one */
			if ( tcp_before(seq_end, g->g_end) ) {
				split_gap(s, i, r, seq, seq_end);
				return;
			}

			dprintf("Backward overlap\n");
			dprintf(" %u-%u -> %u-%u\n",
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

			dprintf("Forward overlap\n");
			dprintf(" %u-%u -> %u-%u\n",
				g->g_begin, g->g_end,
				seq_end, g->g_end);
			g->g_begin = seq_end;
		}
	}
}

/* input packet data in to the reassembly system */
void _tcp_reasm_inject(struct tcp_sbuf *s, uint32_t seq,
			uint32_t len, const uint8_t *buf)
{
	uint32_t seq_end = seq + len;
	uint32_t base, ofs, clen, sseq;
	int is_contig;
	struct tcp_rbuf *r, *lr;

	dprintf("Inject Packet: %u - %u : '%.*s'\n",
		seq, seq + len, len, buf);

	/* Discard everything before contig_seq */
	if ( tcp_before(seq_end, s->s_contig_seq) )
		return;
	if ( tcp_before(seq, s->s_contig_seq) ) {
		uint32_t d = tcp_diff(seq, s->s_contig_seq);
		seq += d;
		buf += d;
		len -= d;
	}
	if ( len == 0 )
		return;

	dprintf(" Trimmed data: %u - %u : '%.*s'\n",
		seq, seq + len, len, buf);

	/* Find or allocate buffer for first byte */
	base = seq_base(s, seq);
	if ( seq == s->s_contig_seq ) {
		r = contig_buf(s, base);
		contig_eat_gaps(s, seq_end);
		is_contig = 1;
	}else{
		assert(tcp_after(seq, s->s_contig_seq));
		is_contig = 0;
		r = discontig_buf(s, base);
		if ( tcp_after(seq, s->s_end) )
			append_gap(s, r, seq, seq_end);
		else
			frob_gaps(s, r, seq, seq_end);
	}

	/* Copy payload data, allocating new buffers as needed */
	dprintf("Copying data to buffers:\n");
	for(sseq = seq; tcp_before(sseq, seq_end); r = rbuf_next(s, r)) {
		struct tcp_rbuf *nr;

		base = seq_base(s, sseq);
		ofs = seq_ofs(s, sseq);
		clen = ((ofs + len) > RBUF_SIZE) ? (RBUF_SIZE - ofs) : len;

		if ( NULL == r ) {
			nr = rbuf_alloc(s, base);
			list_add_tail(&nr->r_list, &s->s_bufs);
			r = nr;
		}else if ( tcp_after(base, r->r_seq) ) {
			nr = rbuf_alloc(s, base);
			dprintf(" ... and put it after %u\n", r->r_seq);
			list_add(&nr->r_list, &r->r_list);
			r = nr;
		}else if ( tcp_before(base, r->r_seq) ) {
			nr = rbuf_alloc(s, base);
			dprintf(" ... and put it before %u\n", r->r_seq);
			list_add_tail(&nr->r_list, &r->r_list);
			r = nr;
		}

		dprintf(" Copy data: base=%u:%u ofs=%u len=%u : '%.*s'\n",
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
		dprintf(" Setting seq_end to %u\n", seq_end);
		s->s_end = seq_end;
	}
}

void _tcp_reasm_free(struct tcp_sbuf *s)
{
	struct tcp_rbuf *r, *tr;
	unsigned int i;

	if ( s->s_bufs.prev ) {
		list_for_each_entry_safe(r, tr, &s->s_bufs, r_list) {
			rbuf_free(r);
		}
	}

	for(i = 0; i < s->s_num_gaps; i++)
		gap_free(s->s_gap[i]);
}

void _tcp_reasm_init(struct tcp_sbuf *s, uint32_t seq_begin)
{
	memset(s, 0, sizeof(*s));
	INIT_LIST_HEAD(&s->s_bufs);
	s->s_begin = seq_begin;
	s->s_reasm_begin = seq_begin;
	s->s_end = seq_begin;
	s->s_contig_seq = seq_begin;
}

uint8_t *_tcp_reassemble(struct tcp_sbuf *s, uint32_t ack, size_t *len)
{
	struct tcp_rbuf *r, *tmp;
	uint8_t *buf, *ptr;
	size_t sz;

	if ( tcp_after(ack, s->s_contig_seq) ) {
		mesg(M_CRIT, "missing segment in tcp stream %u-%u",
			s->s_contig_seq, ack);
		*len = 0;
		return NULL;
	}

	assert(!tcp_before(s->s_reasm_begin, s->s_begin));
	assert(!tcp_before(ack, s->s_reasm_begin));

	sz = tcp_diff(s->s_reasm_begin, s->s_contig_seq);
	ptr = buf = malloc(sz);
	if ( NULL == buf ) {
		*len = 0;
		return NULL;
	}

	*len = sz;

	list_for_each_entry_safe(r, tmp, &s->s_bufs, r_list) {
		uint8_t *end = r->r_base + RBUF_SIZE;
		uint8_t *cp = r->r_base;
		int brk = 0;

		if ( tcp_before(r->r_seq, s->s_reasm_begin) )
			cp += tcp_diff(r->r_seq, s->s_reasm_begin);

		if ( tcp_before(ack, r->r_seq + RBUF_SIZE) ) {
			end -= (RBUF_SIZE - seq_ofs(s, ack));
			brk = 1;
		}

		assert(end >= cp);
		sz = end - cp;

		memcpy(ptr, cp, sz);
		if ( brk )
			break;

		rbuf_free(r);
		ptr += sz;
		if ( s->s_contig == r )
			s->s_contig = NULL;
	}

	if ( list_empty(&s->s_bufs) ) {
		s->s_begin = ack;
		s->s_reasm_begin = ack;
	}else{
		s->s_begin = seq_base(s, ack);
		s->s_reasm_begin = ack;
	}

	assert(!tcp_before(s->s_contig_seq, s->s_begin));
	assert(!tcp_before(s->s_contig_seq, s->s_reasm_begin));
	return buf;
}

int _tcp_reasm_ctor(struct tcpflow *tf)
{
	tf->rbuf_cache = objcache_init("tcp_rbuf", sizeof(struct tcp_rbuf));
	if ( tf->rbuf_cache == NULL )
		return 0;

	tf->data_cache = objcache_init("tcp_data", RBUF_SIZE);
	if ( tf->data_cache == NULL )
		return 0;

	tf->gap_cache = objcache_init("tcp_gap", sizeof(struct tcp_gap));
	if ( tf->gap_cache == NULL )
		return 0;

	return 1;
}

void _tcp_reasm_dtor(struct tcpflow *tf)
{
	//objcache_fini(tf->rbuf_cache);
	//objcache_fini(tf->data_cache);
	//objcache_fini(tf->gap_cache);
}

#if TCP_REASM_TEST_RIG
static void print_gap(uint32_t len)
{
	dprintf("\033[31m");
	while (len--)
		dprintf("#");
	dprintf("\033[0m");
}
static void stream_print(struct tcp_sbuf *s)
{
	struct tcp_rbuf *r;
	struct tcp_gap *n;
	unsigned int i;

	dprintf("Stream begins at %u\n", s->s_begin);
	if ( s->s_contig ) {
		dprintf(" contig = %u - %u\n",
			s->s_contig->r_seq,
			s->s_contig_seq);
	}

	dprintf(" data: '");
	list_for_each_entry(r, &s->s_bufs, r_list) {
		if ( tcp_before(s->s_contig_seq, r->r_seq + RBUF_SIZE) ) {
			dprintf("%.*s",
				seq_ofs(s, s->s_contig_seq), r->r_base);
			break;
		}
		dprintf("%.*s", RBUF_SIZE, r->r_base);
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
			//dprintf("\033[33m%u:%u:%u:%u\033[0m",
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
			dprintf("\033[32m%.*s\033[0m", end - begin, begin);
			if ( !tcp_before(buf_end, nxt) )
				break;
		}
	}

	dprintf("'\n\n");
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
	dprintf("Random seed: %u\n", seed);
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
	dprintf("TCP Reassembly Test Rig.\n"
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
