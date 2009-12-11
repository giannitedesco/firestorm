/*
 * This file is part of Firestorm NIDS
 * Copyright (c) Gianni Tedesco 2002,2003,2004,2008
 * This program is released under the terms of the GNU GPL version 3
 *
 * IP Defragmentation for firestorm
 * ================================
 * This code is a reworking of ip_fragment.c from Linux 2.4.18,
 * it should be relatively straight forward to understand. It's
 * pretty well tested.
 *
 * Should CORRECTLY cope with:
 *  Overlapping fragments
 *  Oversized fragments
 *  Out of order fragments
 *  Timed out packets
 *
 * TODO:
 *  o Fixup configuration args
 *    o per-ip accounting of timeouts
 *    o make everything else global
 *  o Share TCP block allocator (would mean using tree not hash)
 *  o Detect ICMP_TIME_EXCEEDED/ICMP_EXC_FRAGTIME (??)
*/
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <pkt/ip.h>
#include <p_ipv4.h>

#include "tcpip.h"

#if 0
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do{}while(0);
#define dhex_dump(x...) do{}while(0);
#endif

#define IPHASH 127 /* Mersenne prime */
static struct ipq *ipq_latest;
static struct ipq *ipq_oldest;
static struct ipq *frag_hash[IPHASH]; /* IP fragment hash table */
static mempool_t ipf_pool;
static objcache_t ipq_cache;
static objcache_t frag_cache;

/* config: Timeout (in seconds) */
static const timestamp_t timeout = 60 * TIMESTAMP_HZ;

/* config: Don't decode fragments with too low ttl */
static const uint8_t minttl = 1;

/* Statistics */
static unsigned int err_reasm;
static unsigned int err_mem;
static unsigned int err_timeout;
static unsigned int reassembled;

static void fragstruct_free(struct ipfrag *x)
{
	objcache_free2(frag_cache, x);
}

static void ipq_kill(struct ipq *qp)
{
	struct ipfrag *foo, *bar;

	/* Unlink from the list */
	if ( qp->next )
		qp->next->pprev = qp->pprev;
	*qp->pprev = qp->next;

	/* Free the fragments and descriptors */
	for(foo = qp->fragments; foo;) {
		bar = foo;
		foo = foo->next;
		if ( bar->free ) {
			free(bar->fdata);
		}
		fragstruct_free(bar);
	}

	/* Remove from LRU queue */
	if ( qp->next_time)
		qp->next_time->prev_time = qp->prev_time;
	if ( qp->prev_time)
		qp->prev_time->next_time = qp->next_time;
	if ( qp == ipq_oldest )
		ipq_oldest = qp->prev_time;
	if ( qp == ipq_latest )
		ipq_latest = qp->next_time;

	/* Free the ipq itself */
	objcache_free2(ipq_cache, qp);
}

/* Trim down to low memory watermark */
static int ip_evictor(struct ipq *cq)
{
	struct ipq *kill;

	err_mem++;

	if ( !ipq_oldest )
		return 0;
	if ( ipq_oldest == cq )
		kill = ipq_oldest->next;
	else
		kill = ipq_oldest;

	if ( kill ) {
		ipq_kill(kill);
		return 1;
	}

	return 0;
}

static struct ipfrag *fragstruct_alloc(struct ipq *qp)
{
	struct ipfrag *ret;

again:
	ret = objcache_alloc(frag_cache);
	if ( NULL == ret ) {
		if ( ip_evictor(qp) )
			goto again;
	}

	return ret;
}

/* Hash function for hash lookup */
static unsigned int ipq_hashfn(uint16_t id,
				uint32_t saddr,
				uint32_t daddr,
				uint8_t proto)
{
	unsigned int h = saddr ^ daddr;
	h ^= (h >> 16) ^ id;
	h ^= (h >> 8) ^ proto;
	return h % IPHASH;
}

/*
 * Report ip fragmentation violations.
 */
static void alert_teardrop(struct _pkt *p)
{
	mesg(M_WARN, "ipdefrag: teardrop");
}
static void alert_oversize(struct _pkt *p)
{
	mesg(M_WARN, "ipdefrag: oversize fragments");
}
static void alert_attack(struct _pkt *p)
{
	mesg(M_WARN, "ipdefrag: frag attack");
}
static void alert_boink(struct _pkt *p)
{
	mesg(M_WARN, "ipdefrag: boink");
}
static void alert_timedout(struct _pkt *p)
{
	mesg(M_WARN, "ipdefrag: timeout");
}

/* Reassemble a complete set of fragments */
static void reassemble(struct ipq *qp,
				struct _pkt *pkt)
{
	struct ipfrag *f;
	struct pkt_iphdr *iph;
	int len = 0;
	uint8_t *buf, *ptr;
	struct _pkt new;

	assert(qp->len <= 0xffff);

	if ( !qp->fragments )
		goto err;

	iph = qp->fragments->fdata;
	qp->len += iph->ihl << 2;

	/* Allocate the frankenpacket buffer */
	ptr = buf = malloc(qp->len);
	if ( buf == NULL )
		goto err;

	/* Copy all the fragments in to the new buffer */
	dmesg(M_DEBUG, "Reassemble: %u bytes", qp->len);

	/* Do the header */
	dmesg(M_DEBUG, " * %u byte header", iph->ihl << 2);
	memcpy(ptr, qp->fragments->fdata, iph->ihl << 2);
	ptr += iph->ihl << 2;
	len += iph->ihl << 2;

	for(f = qp->fragments; f; f = f->next) {
		dmesg(M_DEBUG, " * %u bytes @ %u", f->len, f->offset);
		memcpy(ptr, f->data, f->len);
		ptr += f->len;
		len += f->len;
		if ( len >= qp->len )
			break;
	}

	/* Fixup the IP header */
	iph = (void *)buf;
	iph->frag_off = 0;
	iph->tot_len = sys_be16(len);
	iph->csum = 0;
	iph->csum = _ip_csum(iph);

	dhex_dump(buf, qp->len, 16);

	new.pkt_source = pkt->pkt_source;
	new.pkt_ts = qp->time;
	new.pkt_base = buf;
	new.pkt_len = new.pkt_caplen = qp->len;
	new.pkt_end = new.pkt_base + new.pkt_len;

	new.pkt_dcb = NULL;

	if ( !decode_pkt_realloc(&new, DECODE_DEFAULT_MIN_LAYERS) )
		goto err_free;

	reassembled++;

	decode(&new, &_ipv4_decoder);
	pkt_inject(&new);

	decode_pkt_realloc(&new, 0);
	free(buf);
	return;

err_free:
	free(buf);
err:
	err_reasm++;
}

static struct ipq *ip_frag_create(unsigned int hash,
					const struct pkt_iphdr *iph)
{
	struct ipq *q;

again:
	q = objcache_alloc0(ipq_cache);
	if ( q == NULL ) {
		if ( ip_evictor(NULL) )
			goto again;
		return NULL;
	}

	q->id = iph->id;
	q->saddr = iph->saddr;
	q->daddr = iph->daddr;
	q->protocol = iph->protocol;
	q->next = frag_hash[hash];
	if ( q->next )
		q->next->pprev = &q->next;
	frag_hash[hash] = q;
	q->pprev = &frag_hash[hash];

	return q;
}

/* Find (or create) the ipq for this IP fragment */
static struct ipq *ip_find(const struct pkt_iphdr *iph,
				unsigned int *hash,
				struct _pkt *pkt)
{
	struct ipq *qp;

	*hash = ipq_hashfn(iph->id, iph->saddr,
				iph->daddr, iph->protocol);

	for(qp = frag_hash[*hash]; qp; qp = qp->next) {
		if ( (qp->id == iph->id) &&
			(qp->saddr == iph->saddr) &&
			(qp->daddr == iph->daddr) &&
			(qp->protocol == iph->protocol) ) {
			return qp;
		}
	}

	qp = ip_frag_create(*hash, iph);
	if ( qp )
		qp->time = pkt->pkt_ts;
	return qp;
}

/* If a fragment is too old then zap it */
static int expired(struct _pkt *pkt, struct ipq *qp)
{
	if ( time_after(pkt->pkt_ts, qp->time + timeout) ) {
		err_timeout++;
		return 0;
	}

	return 1;
}

static int check_timeouts(struct _pkt *pkt, struct ipq *qp)
{
	/* Check our timeout */
	if ( !expired(pkt, qp) ) {
		/* We alert if we actually see a fragment
		 * arrive after the timeout because that
		 * is suspicious (read: evasive)
		*/
		alert_timedout(pkt);
		ipq_kill(qp);
		return 0;
	}

	/* Move qp to head of LRU list */
	if ( qp->next_time)
		qp->next_time->prev_time = qp->prev_time;
	if ( qp->prev_time)
		qp->prev_time->next_time = qp->next_time;
	if ( qp == ipq_oldest )
		ipq_oldest = qp->prev_time;
	if ( qp == ipq_latest )
		ipq_latest = qp->next_time;
	qp->next_time = ipq_latest;
	qp->prev_time = NULL;
	if ( !ipq_oldest )
		ipq_oldest = qp;
	if ( ipq_latest )
		ipq_latest->prev_time = qp;
	ipq_latest = qp;

	/* Check timeouts on other fragment queues */
	while ( ipq_oldest ){
		if ( expired(pkt, ipq_oldest) )
			break;

		/* this can't kill qp from under us because
		 * we already know we haven't timed out */
		ipq_kill(ipq_oldest);
		return 0;
	}

	/* The time for the reassembled packet is equal
	 * to the time of the last packet recieved. This
	 * makes things sane in the sense that time won't
	 * be seen to be going backwards by the higher layers!
	 */
	qp->time = pkt->pkt_ts;

	return 1;
}

static void hash_mtf(unsigned int hash, struct ipq *qp)
{
	/* Move to front heuristic */
	if ( qp->next )
		qp->next->pprev = qp->pprev;
	*qp->pprev = qp->next;
	if ( (qp->next = frag_hash[hash]) )
		qp->next->pprev = &qp->next;
	frag_hash[hash] = qp;
	qp->pprev = &frag_hash[hash];
}

static int queue_fragment(unsigned int hash,
				struct ipq *qp,
				struct _pkt *pkt,
				const struct pkt_iphdr *iph)
{
	struct ipfrag *prev, *next, *me;
	int flags, offset;
	int ihl, end, len;
	int chop = 0;

	if ( !check_timeouts(pkt, qp) )
		return 0;

	hash_mtf(hash, qp);

	/* Now we can get on with queueing the packet.. */
	ihl = iph->ihl << 2;
	len = sys_be16(iph->tot_len);

	offset = sys_be16(iph->frag_off);
	flags = offset & ~IP_OFFMASK;
	offset &= IP_OFFMASK;
	offset <<= 3; /* 8 byte granularity */

	end = offset + len - ihl;

	if ( (flags & IP_MF) == 0 ) {
		if ( (end < qp->len) ||
			((qp->last_in & LAST_IN) && (end != qp->len))) {
			alert_teardrop(pkt);
			return 0;
		}
		qp->last_in |= LAST_IN;
		qp->len = end;
	}else{
		if ( end & 7 ) {
			/* Don't drop the packet stupid! Modern
			 * stacks mask off 0x7 so if we ditch the
			 * frag as invalid we could be evaded. */
			alert_boink(pkt);
		}

		/* Non-terminal fragments must be multiples of
		 * 8 bytes so mask off low-order bits */
		end &= ~7;

		if ( end > qp->len ) {
			if (qp->last_in & LAST_IN) {
				alert_attack(pkt);
				return 0;
			}
			qp->len = end;
		}
	}

	if ( end == offset ) {
		alert_attack(pkt);
		return 0;
	}

	/* Don't bother wasting any more resources
	 * when we know the packet is oversize (invalid) */
	if ( qp->len > 0xffff ) {
		alert_oversize(pkt);
		return 0;
	}

	/* Insert data into fragment chain */
	me = fragstruct_alloc(qp);
	if ( me == NULL )
		return 0;

	/* Find out where to insert this fragment in the list */
	for(prev = NULL, next = qp->fragments; next; next = next->next) {
		if ( next->offset >= offset )
			break;
		prev = next;
	}

	/* Check we don't overlap the previous fragment */
	if ( prev ) {
		int i = (prev->offset + prev->len) - offset;

		if ( i > 0 ) {
			offset += i;
			chop = i;
			len -= i;

			if ( end <= offset ) {
				alert_attack(pkt);
				return 0;
			}
		}
	}

	/* Make sure we don't overlap next packets */
	while( next && (next->offset < end) ) {
		int i = end - next->offset;

		if ( i < next->len ) {
			/* Eat head of the next overlapped fragment
			 * and leave the loop. The next ones cannot
			 * overlap. */
			next->offset += i;
			next->len -= i;
			next->data += i;
			break;
		}else{
			struct ipfrag *free_it = next;

			/* Old fragment is completely overriden
			 * with new one. Drop it */
			next = next->next;
			if ( prev ){
				prev->next = next;
			}else{
				qp->fragments = next;
			}

			qp->meat -= free_it->len;
			fragstruct_free(free_it);
		}
	}

	/* Make the fragment */
	me->len = len - chop;
	me->offset = offset;
	me->len -= ihl;
	if ( offset ) {
		chop = ihl;
	} else {
		chop = 0;
	}

#if 1
	do {
		unsigned int alen = me->len;

		if ( !offset )
			alen += ihl;

		me->fdata = malloc(alen);
		if ( me->fdata == NULL ) {
			fragstruct_free(me);
			return 0;
		}

		memcpy(me->fdata, ((char *)iph) + chop, alen);
		me->free = 1;
		me->flen = alen;
	}while(0);
#else
	/* FIXME: IP defragmentation could be zerocopy for
	 * mmapped tcpdump files, but then the ip header
	 * can't be fixed up at reassemble time...
	*/
	me->fdata = ((void *)iph) + chop;
	me->free = 0;
#endif

	me->data = me->fdata;

	if ( !offset )
		me->data += ihl;

	/* Insert the fragment */
	me->next = next;
	if ( prev ) {
		prev->next = me;
	}else{
		qp->fragments = me;
	}

	/* Finish up */
	qp->meat += me->len;
	if ( !offset )
		qp->last_in |= FIRST_IN;

	dmesg(M_DEBUG, "0x%x: got a fragment (%u/%u)",
		(unsigned int)qp,
		qp->meat, qp->len);

	if ( qp->last_in == (FIRST_IN|LAST_IN) && qp->meat == qp->len )
		return 1;

	return 0;
}

void _ipdefrag_track(pkt_t pkt, dcb_t dcb_ptr)
{
	const struct pkt_iphdr *iph;
	struct ipfrag_dcb *dcb;
	unsigned int hash;
	struct ipq *q;

	dcb = (struct ipfrag_dcb *)dcb_ptr;
	iph = dcb->ip_iph;

	/* Ignore packets with ttl < min_ttl */
	if ( iph->ttl < minttl )
		return;

	q = ip_find(iph, &hash, pkt);
	if ( q == NULL )
		return;

	if ( queue_fragment(hash, q, pkt, iph) ) {
		reassemble(q, pkt);
		ipq_kill(q);
	}
}

void _ipdefrag_dtor(void)
{
	mesg(M_INFO, "ipdefrag: %u reassembled packets, "
		"%u reasm errors, %u timeouts, %u oom",
		reassembled, err_reasm, err_timeout, err_mem);

	mempool_free(ipf_pool);
}

int _ipdefrag_ctor(void)
{
	if ( minttl > 255 ) {
		mesg(M_ERR, "ipdefrag: minttl must be < 256");
		return 0;
	}

	mesg(M_INFO, "ipdefrag: minttl=%u timeout=%us",
		minttl, timeout / TIMESTAMP_HZ);

	if ( timeout < (10 * TIMESTAMP_HZ) ||
		timeout > (120 * TIMESTAMP_HZ) ) {
		mesg(M_WARN, "ipdefrag: timeout is unreasonable - "
			"you will be vulnerable to evasion!");
	}

	ipf_pool = mempool_new("ipdefrag", 2);
	ipq_cache = objcache_init(ipf_pool, "ipq", sizeof(struct ipq));
	frag_cache = objcache_init(ipf_pool, "ipfrag", sizeof(struct ipfrag));
	if ( ipq_cache == NULL || frag_cache == NULL )
		return 0;

	return 1;
}
