/* Copyright (c) Gianni Tedesco 2005,2006,2007,2008
 * Released under the terms of the GNU GPL v3
 *
 * This is a fast tcp stream reassembly module which manages allocation of
 * contiguous chunks of memory (say 2 to the power of 7-9 bytes) but it also
 * use a red-black style interval encoding tree to manage the packet sized
 * areas within the chunks. This allows us to receive duplicate and out of
 * order packets and deal with them efficiently. It also handles sequence
 * overflows (even within 1 node).
*/
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_flow.h>
#include <pkt/ip.h>
#include <pkt/tcp.h>
#include <pkt/icmp.h>
#include "p_ipv4.h"

#if 0
#define dmesg mesg
#else
#define dmesg(...) do {} while(0);
#endif

#define RBUF_SHIFT	9
#define RBUF_SIZE	(1<<RBUF_SHIFT)
#define RBUF_MASK	(RBUF_SIZE - 1)
#define RBUF_BASE	(~RBUF_MASK)

struct rbuf {
	uint32_t seq_begin;
	uint8_t buf[RBUF_SIZE];
};

/* This defines a node in the tree, each node represents a range of bytes
 * in the tcp stream.
 */
struct tcpr_node {
	struct tcpr_node *parent;
#define CHILD_LEFT 0
#define CHILD_RIGHT 1
	struct tcpr_node *child[2];
#define COLOR_RED 0 /* parent is black */
#define COLOR_BLACK 1 /* root and NILs are black */
	int color;
#define VAL_BEGIN 0 /* begin sequence # */
#define VAL_END 1 /* end sequence # */
	uint32_t val[2];
	struct rbuf *rbuf;
};

static uint32_t tcp_diff(uint32_t s1, uint32_t s2)
{
	if ( s2 < s1 )
		return (0xffffffff - s1) + s2 + 1;
	return (s2 - s1);
}

/* in-line accessors for states, to hide the array uglyness */
static uint32_t node_begin(struct tcpr_node *n)
{
	return n->val[VAL_BEGIN];
}
static uint32_t node_end(struct tcpr_node *n)
{
	return n->val[VAL_END];
}
static uint32_t node_len(struct tcpr_node *n)
{
	return tcp_diff(n->val[VAL_BEGIN], n->val[VAL_END]);
}

/* Rbuf allocation
 * TODO: ditch malloc for a preallocated stack + eviction
 */
static struct rbuf *rbuf_alloc(struct tcp_sbuf *s, uint32_t seq)
{
	struct rbuf *ret;

	ret = calloc(1, sizeof(*ret));
	if ( ret ) {
		ret->seq_begin = (seq - s->begin) & RBUF_BASE;
		ret->seq_begin += s->begin;
		/* XXX: Colour the space to catch bugs */
		memset(ret->buf, '_', sizeof(ret->buf));
		dmesg(M_DEBUG, "  rbuf_alloc: seq_begin=%u", ret->seq_begin);
	}

	return ret;
}

static void rbuf_free(struct rbuf *r)
{
	free(r);
}

/* Node allocation
 * TODO: ditch malloc for a preallocated stack + eviction
 */
static struct tcpr_node *node_alloc(void)
{
	struct tcpr_node *ret;
	ret = calloc(1, sizeof(*ret));
	return ret;
}

static void node_free(struct tcpr_node *n)
{
	free(n);
}

/* For any given node, find the previous or next node */
static struct tcpr_node *node_prev_next(struct tcpr_node *n, int prev)
{
	if ( n == NULL )
		return NULL;

	if ( n->child[prev ^ 1] ) {
		n = n->child[prev ^ 1];
		while( n->child[prev ^ 0] )
			n = n->child[prev ^ 0];
		return n;
	}else{
		while(n->parent && n != n->parent->child[prev ^ 0] )
			n = n->parent;

		return n->parent;
	}
}
static struct tcpr_node *node_next(struct tcpr_node *n)
{
	return node_prev_next(n, 0);
}
static struct tcpr_node *node_prev(struct tcpr_node *n)
{
	return node_prev_next(n, 1);
}

/* Here we handle left/right rotations (the 2 are symmetrical) which are
 * sometimes needed to rebalance the tree after modifications
*/
static void do_rotate(struct tcp_sbuf *s, struct tcpr_node *n, int side)
{
	struct tcpr_node *opp = n->child[1 ^ side];

	if ( (n->child[1 ^ side] = opp->child[0 ^ side]) )
		opp->child[0 ^ side]->parent = n;
	opp->child[0 ^ side] = n;

	if ( (opp->parent = n->parent) ) {
		if ( n == n->parent->child[0 ^ side] ) {
			n->parent->child[0 ^ side] = opp;
		}else{
			n->parent->child[1 ^ side] = opp;
		}
	}else{
		s->root = opp;
	}
	n->parent = opp;
}

/* Re-balance the tree after an insertion */
static void rebalance(struct tcp_sbuf *s, struct tcpr_node *n)
{
	struct tcpr_node *parent, *gparent, *uncle;
	int side;

	while ( (parent = n->parent) ) {

		/* Recursion termination, the tree is balanced */
		if ( parent->color == COLOR_BLACK )
			break;

		/* When your structures have symmetry, your code can
		 * be half the size!
		 */
		gparent = parent->parent;
		side = (parent == gparent->child[1]);
		uncle = gparent->child[1 ^ side];

		/* Check to see if we can live with just recoloring */
		if ( uncle && (uncle->color == COLOR_RED) ) {
			gparent->color = COLOR_RED;
			parent->color = COLOR_BLACK;
			uncle->color = COLOR_BLACK;
			n = gparent;
			continue;
		}

		/* Check to see if we need to do double rotation */
		if ( n == parent->child[1 ^ side] ) {
			struct tcpr_node *t;

			do_rotate(s, parent, 0 ^ side);
			t = parent;
			parent = n;
			n = t;
		}

		/* If not, we do a single rotation */
		parent->color = COLOR_BLACK;
		gparent->color = COLOR_RED;
		do_rotate(s, gparent, 1 ^ side);
	}

	s->root->color = COLOR_BLACK;
}

/* Re-balance a tree after deletion, probably the most complex bit... */
static void delete_rebalance(struct tcp_sbuf *s,
				struct tcpr_node *n, struct tcpr_node *parent)
{
	struct tcpr_node *other;
	int side;

	while ( ((n == NULL) || n->color == COLOR_BLACK) ) {
		if ( n == s->root)
			break;

		side = (parent->child[1] == n);
		other = parent->child[1 ^ side];

		if ( other->color == COLOR_RED ) {
			other->color = COLOR_BLACK;
			parent->color = COLOR_RED;
			do_rotate(s, parent, 0 ^ side);
			other = parent->child[1 ^ side];
		}

		if ( ((other->child[0 ^ side] == NULL) ||
			(other->child[0 ^ side]->color == COLOR_BLACK)) &&
			((other->child[1 ^ side] == NULL) ||
			(other->child[1 ^ side]->color == COLOR_BLACK)) ) {
			other->color = COLOR_RED;
			n = parent;
			parent = n->parent;
		}else{
			if ( (other->child[1 ^ side] == NULL) ||
			(other->child[1 ^ side]->color == COLOR_BLACK) ) {
				struct tcpr_node *opp;

				if ( (opp = other->child[0 ^ side]) )
					opp->color = COLOR_BLACK;

				other->color = COLOR_RED;
				do_rotate(s, other, 1 ^ side);
				other = parent->child[1 ^ side];
			}

			other->color = parent->color;
			parent->color = COLOR_BLACK;
			if ( other->child[1 ^ side] )
				other->child[1 ^ side]->color = COLOR_BLACK;
			do_rotate(s, parent, 0 ^ side);
			n = s->root;
			break;
		}
	}

	if ( n )
		n->color = COLOR_BLACK;
}

static void delete_node(struct tcp_sbuf *s, struct tcpr_node *n)
{
	struct tcpr_node *child, *parent;
	int color;

	if ( n->child[0] && n->child[1] ) {
		struct tcpr_node *old = n, *lm;

		/* If we have 2 children, go right, and then find the leftmost
		 * node in that subtree, this is the one to swap in to replace
		 * our deleted node
		 */
		n = n->child[1];
		while ( (lm = n->child[0]) != NULL )
			n = lm;

		child = n->child[1];
		parent = n->parent;
		color = n->color;

		if ( child )
			child->parent = parent;

		if ( parent ) {
			if ( parent->child[0] == n )
				parent->child[0] = child;
			else
				parent->child[1] = child;
		}else
			s->root = child;

		if ( n->parent == old )
			parent = n;

		n->parent = old->parent;
		n->color = old->color;
		n->child[0] = old->child[0];
		n->child[1] = old->child[1];

		if ( old->parent ) {
			if ( old->parent->child[0] == old )
				old->parent->child[0] = n;
			else
				old->parent->child[1] = n;
		}else
			s->root = n;

		old->child[0]->parent = n;
		if ( old->child[1] )
			old->child[1]->parent = n;

		goto rebalance;
	}

	/* ... or if a child is non-NULL then we can swap that in */
	if ( n->child[0] == NULL ) {
		child = n->child[1];
	}else if ( n->child[1] == NULL ) {
		child = n->child[0];
	}

	parent = n->parent;
	color = n->color;

	if ( child )
		child->parent = parent;

	if ( parent ) {
		if ( parent->child[0] == n )
			parent->child[0] = child;
		else
			parent->child[1] = child;
	}else
		s->root = child;

rebalance:
	if ( color == COLOR_BLACK )
		delete_rebalance(s, child, parent);
}

/* Copy packet data in to the rbuf */
static void copy_to_buffer(struct rbuf *rbuf, const void *buf,
				uint32_t begin, uint32_t end)
{
	uint32_t ofs = tcp_diff(rbuf->seq_begin, begin);

	assert(ofs < RBUF_SIZE);

	dmesg(M_DEBUG, "  copying %u bytes at offset %u",
		tcp_diff(begin, end), ofs);
	memcpy(rbuf->buf + ofs, buf, end - begin);
}

/* Compare 2 sequence numbers to see if they are in the same rbuf for
 * a given stream
 */
static int rbuf_cmp(struct tcp_sbuf *s, uint32_t a, uint32_t b)
{
	return ((a - s->begin) & RBUF_BASE) - ((b - s->begin) & RBUF_BASE);
}


/* Handle the case where a new packet is either merging with an existing node
 * (ie. not setting up a new discontig area) or fills the gap between 2
 * discontiguous nodes and we need to merge them all together.
*/
static struct tcpr_node *merge_node(struct tcp_sbuf *s, struct tcpr_node *prev,
				struct tcpr_node *next, uint32_t begin,
				uint32_t end)
{
	uint32_t newbegin, newend;
	struct tcpr_node *first, *last, *t, *tmp;

	/* Find first and last nodes to merge */
	if ( !prev || rbuf_cmp(s, node_begin(prev), begin) ||
		tcp_before(node_end(prev), begin) ) {
		first = next;
	}else{
		for(first=t=prev; t && rbuf_cmp(s, node_begin(t), begin);
			first=t, t=node_prev(t) )
			if ( tcp_before(node_end(t), begin) )
				break;
	}

	if ( !next || rbuf_cmp(s, node_begin(next), begin) ||
		tcp_after(node_begin(next), end) ) {
		last = prev;
	}else{
		for(last=t=next; t && rbuf_cmp(s, node_end(t), end);
			last=t, t=node_next(t) ) {
			if ( tcp_after(node_begin(t), end) )
				break;
		}
	}

	/* Figure out new buffer area */
	newbegin = node_begin(first);
	if ( tcp_before(begin, newbegin) )
		newbegin = begin;

	newend = node_end(last);
	if ( tcp_after(end, newend) )
		newend = end;

	/* Delete the old nodes */
	for(t=node_next(first); t && tcp_before(node_begin(t), newend); t=tmp) {
		tmp = node_next(t);
		delete_node(s, t);
		node_free(t);
	}

	/* Finish up by replacing the old buffer with the new */
	first->val[VAL_BEGIN] = newbegin;
	first->val[VAL_END] = newend;

	dmesg(M_DEBUG, "  merged to new area: %u-%u", newbegin, newend);

	return first;
}

/* Allocates a new node ready for insertion in to the tree with the give
 * particulars.
 */
static struct tcpr_node *new_node(struct tcp_sbuf *s, struct rbuf *rb,
				uint32_t begin, uint32_t end,
				const char *buf)
{
	struct tcpr_node *n;
	size_t len;

	if ( rb == NULL )
		rb = rbuf_alloc(s, begin);

	n = node_alloc();
	if ( n == NULL ) {
		rbuf_free(rb);
		return NULL;
	}

	n->val[VAL_BEGIN] = begin;
	n->val[VAL_END] = end;
	n->color = COLOR_RED;
	n->rbuf = rb;
	len = node_len(n);

	copy_to_buffer(n->rbuf, buf, begin, end);

	return n;
}

/* Insert a node in to the tree */
static void reasm_pkt(struct tcp_sbuf *s, uint32_t seq,
			uint32_t len, const void *buf)
{
	struct tcpr_node *n, *parent, **p, *prev, *next;
	uint32_t begin = seq;
	uint32_t end = seq + len;
	struct rbuf *rb = NULL;
	int side;

	dmesg(M_DEBUG, " Split to %u-%u len=%u", seq, seq + len, len);

	for(p=&s->root, n = parent = NULL; *p; ) {
		parent = *p;

		if ( !tcp_before(begin, node_begin(parent)) &&
			!tcp_after(end, node_end(parent)) ) {
			dmesg(M_DEBUG, "  retransmitted segment "
				"(discarded) (%u-%u)",
				node_begin(parent), node_end(parent));
			return;
		}else if ( tcp_before(begin, node_begin(parent))) {
			side = 0;
		}else if ( tcp_after(begin, node_begin(parent))) {
			side = 1;
		}else{
			break;
		}

		p = &(*p)->child[side];
	}

	if ( parent == NULL ) {
		prev = next = NULL;
		goto do_insert;
	}

	if ( p == &parent->child[0] ) {
		prev = node_prev(parent);
		next = parent;
	}else{
		prev = parent;
		next = node_next(parent);
	}

	if ( (next && !tcp_before(end, node_begin(next)) &&
		!rbuf_cmp(s, begin, node_begin(next))) ||
		(prev && !tcp_after(begin, node_end(prev)) &&
		!rbuf_cmp(s, begin, node_begin(prev))) ) {
		n = merge_node(s, prev, next, begin, end);
		/* TODO: Need favour-old mode too */
		copy_to_buffer(n->rbuf, buf, begin, end);
		return;
	}

do_insert:
	if ( prev && !rbuf_cmp(s, begin, node_begin(prev)) )
		rb = prev->rbuf;
	else if ( next && !rbuf_cmp(s, begin, node_begin(next)) )
		rb = next->rbuf;
	else
		rb = NULL;

	n = new_node(s, rb, begin, end, buf);
	if ( n == NULL )
		return;

	n->parent = parent;
	*p = n;

	rebalance(s, n);

	dmesg(M_DEBUG, "  inserted new area: %u-%u", begin, end);
}

/* input packet data in to the reassembly system */
void _tcp_reasm_inject(struct tcp_sbuf *s, uint32_t seq,
			uint32_t len, const void *buf)
{
	uint32_t rbegin, rend;

	dmesg(M_DEBUG, "Got packet: %x-%x: (%x-%x)",
		seq, seq + len,
		(seq & RBUF_BASE) >> RBUF_SHIFT,
		((seq + len) & RBUF_BASE) >> RBUF_SHIFT);

	if ( tcp_before(seq + len, s->reasm_begin) )
		return;

	if ( tcp_before(seq, s->reasm_begin) ) {
		seq = s->reasm_begin;
		len -= tcp_diff(seq, s->reasm_begin);
	}

	assert(len);

	/* Check if the packet must split accross multiple rbufs */
	rbegin = ((seq - s->begin) & RBUF_BASE) >> RBUF_SHIFT;
	rend = (((seq - s->begin) + len) & RBUF_BASE) >> RBUF_SHIFT;

	for(; rbegin < rend; rbegin++) {
		uint32_t nlen;

		nlen = ~((seq - s->begin) & RBUF_MASK) & RBUF_MASK;
		nlen++;

		reasm_pkt(s, seq, nlen, buf);

		len -= nlen;
		buf += nlen;
		seq += nlen;
	}

	reasm_pkt(s, seq, len, buf);
}

/* Find all contiguous nodes starting from the left-most node in the tree */
static struct tcpr_node *get_contig_areas(struct tcp_sbuf *s,
				void(*cbfn)(struct tcpr_node *n, void *ptr),
				void *priv)
{
	struct tcpr_node *t, *n;

	for(n=t=s->root; t; n=t, t=t->child[0])
		/* nothing */;

	while ( (t = n) ) {
		if ( cbfn )
			(*cbfn)(n, priv);
		n = node_next(n);
		if ( n == NULL )
			return t;

		if ( tcp_before(node_end(t), node_begin(n)) )
			return t;
	}

	return NULL;
}

/* Reassemble a range in to a pre-existing buffer */
static void do_reassemble(struct tcp_sbuf *s, uint32_t seq,
				void *buf, size_t len)
{
	struct tcpr_node *t, *n;
	uint32_t end = seq + len;

	for(n = t = s->root; t; n = t, t = t->child[0])
		/* nothing */;

	for(; t = node_next(n), n ; n = t) {
		size_t sz;
		void *ptr;

		if ( tcp_before(node_end(n), seq) )
			continue;

		if ( tcp_after(node_begin(n), end) )
			return;

		sz = tcp_diff(n->rbuf->seq_begin, node_begin(n));
		ptr = n->rbuf->buf + sz;
		sz = node_len(n);

		if ( tcp_after(node_end(n), end) )
			sz -= tcp_diff(end, node_end(n));

		assert(len >= sz);
		memcpy(buf, ptr, sz);
		buf += sz;
		len -= sz;
	}
}

/* Get rid of all data from beginning of buffer up to seq_end */
static void dump_buffer(struct tcp_sbuf *s, uint32_t seq_end)
{
	struct tcpr_node *t, *n;
	struct rbuf *r;

	for(n=t=s->root; t; n=t, t=t->child[0])
		/* nothing */;

	for(r = NULL; t = node_next(n), n ; n = t) {
		if ( tcp_after(node_begin(n), seq_end) )
			break;

		s->begin = n->rbuf->seq_begin;
		if ( r != n->rbuf ) {
			r = n->rbuf;
			rbuf_free(r);
		}
		delete_node(s, n);
		node_free(n);
	}

	s->reasm_begin = seq_end;

	assert(!tcp_after(s->begin, s->reasm_begin));
}

void _tcp_reasm_free(struct tcp_sbuf *s)
{
	struct tcpr_node *t, *n;
	struct rbuf *r;

	for(n = t = s->root; t; n = t, t = t->child[0])
		/* nothing */;

	for(r = NULL; t = node_next(n), n ; n = t) {
		if ( r != n->rbuf ) {
			r = n->rbuf;
			rbuf_free(r);
		}
		delete_node(s, n);
		node_free(n);
	}
}

uint8_t *_tcp_reassemble(struct tcp_sbuf *s, uint32_t ack, size_t *len)
{
	struct tcpr_node *last;
	uint8_t *ptr;

	last = get_contig_areas(s, NULL, NULL);
	if ( last == NULL )
		return NULL;

	if ( tcp_after(ack, node_end(last)) ) {
		mesg(M_CRIT, "tcp_reasm: missed %x-%x segment (%u bytes)",
			node_end(last), ack,
			tcp_diff(node_end(last), ack));
	}

	assert(tcp_before(s->reasm_begin, ack));

	*len = tcp_diff(s->reasm_begin, ack);
	if ( *len == 0 )
		return NULL;

	dmesg(M_DEBUG, "Ack %x-%x (%u bytes)",
		s->reasm_begin, ack, *len);

	ptr = malloc(*len);
	if ( ptr == NULL ) {
		mesg(M_CRIT, "tcp_reasm: OOM on %u byte reassemblygram %x-%x",
			*len, s->reasm_begin, ack);
		return NULL;
	}

	/* Put acked data in to a contiguous buffer */
	do_reassemble(s, s->reasm_begin, ptr, *len);

	dump_buffer(s, s->reasm_begin);

	return ptr;
}
