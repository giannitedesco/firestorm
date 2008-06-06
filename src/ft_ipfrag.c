/*
 * This file is part of Firestorm NIDS
 * Copyright (c) Gianni Tedesco 2002,2003,2004.2008
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
#include <f_flow.h>
#include <pkt/ip.h>
#include "p_ipv4.h"

#if 0
#define dmesg mesg
#define dhex_dump hex_dump
#else
#define dmesg(x...) do{}while(0);
#define dhex_dump(x...) do{}while(0);
#endif

#define IPHASH (1 << 7) /* Must be a power of two */
struct ipdefrag {
	struct ipq *ipq_latest;
	struct ipq *ipq_oldest;
	size_t mem;
	struct ipq *hash[IPHASH]; /* IP fragment hash table */
};

/* config: high and low memory water marks */
static const size_t mem_hi = 4 << 20;
static const size_t mem_lo = 3 << 20;

/* config: Timeout (in seconds) */
static const timestamp_t timeout = 60 * TIMESTAMP_HZ;

/* config: Don't decode fragments with too low ttl */
static const unsigned int minttl = 1;

/* Statistics */
static unsigned int err_reasm;
static unsigned int err_mem;
static unsigned int err_timeout;
static unsigned int reassembled;

static struct ipfrag *fragstruct_alloc(struct ipdefrag *ipd)
{
	struct ipfrag *ret;

	ret = malloc(sizeof(*ret));
	if ( ret )
		ipd->mem += sizeof(*ret);

	return ret;
}

static void fragstruct_free(struct ipdefrag *ipd, struct ipfrag *x)
{
	free(x);
	ipd->mem -= sizeof(*x);
}

/* Hash function for ipd->hash lookup */
static unsigned int ipq_hashfn(uint16_t id,
				uint32_t saddr,
				uint32_t daddr,
				uint8_t proto)
{
	unsigned int h = saddr ^ daddr;
	h ^= (h >> 16) ^ id;
	h ^= (h >> 8) ^ proto;
	return h & (IPHASH - 1);
}

/*
 * Report ip fragmentation violations.
 */
static void alert_teardrop(struct _pkt *p)
{
}
static void alert_oversize(struct _pkt *p)
{
}
static void alert_attack(struct _pkt *p)
{
}
static void alert_boink(struct _pkt *p)
{
}
static void alert_oom(struct _pkt *p)
{
}
static void alert_timedout(struct _pkt *p)
{
}

static void ipq_kill(struct ipdefrag *ipd, struct ipq *qp)
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
			ipd->mem -= bar->flen;
		}
		fragstruct_free(ipd, bar);
	}

	/* Remove from LRU queue */
	if ( qp->next_time)
		qp->next_time->prev_time = qp->prev_time;
	if ( qp->prev_time)
		qp->prev_time->next_time = qp->next_time;
	if ( qp == ipd->ipq_oldest )
		ipd->ipq_oldest = qp->prev_time;
	if ( qp == ipd->ipq_latest )
		ipd->ipq_latest = qp->next_time;

	/* Free the ipq itself */
	free(qp);
	ipd->mem -= sizeof(struct ipq);
}

static void frankenpkt_dtor(struct _pkt *pkt)
{
	decode_pkt_realloc(pkt, 0);
	free(pkt->pkt_base);
}

/* Reassemble a complete set of fragments */
static struct _pkt *reassemble(struct ipdefrag *ipd, struct ipq *qp, source_t s)
{
	struct ipfrag *f;
	struct pkt_iphdr *iph;
	int len = 0;
	uint8_t *buf, *ptr;
	struct _pkt *ret = NULL;

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

	ret = pkt_alloc(s);
	if ( ret == NULL )
		goto err_free_buf;

	ret->pkt_ts = qp->time;
	ret->pkt_base = buf;
	ret->pkt_len = ret->pkt_caplen = qp->len;
	ret->pkt_end = ret->pkt_base + ret->pkt_len;

	if ( !decode_pkt_realloc(ret, DECODE_DEFAULT_MIN_LAYERS) )
		goto err_free_pkt;

	ret->pkt_dtor = frankenpkt_dtor;

	/* TODO: Inject the packet back in to the flow */
	decode(ret, &_ipv4_decoder);
	reassembled++;

	return ret;

err_free_pkt:
	pkt_free(ret);
err_free_buf:
	free(buf);
err:
	err_reasm++;
	return ret;
}

static struct ipq *ip_frag_create(struct ipdefrag *ipd, unsigned int hash,
					const struct pkt_iphdr *iph)
{
	struct ipq *q;

	q = calloc(1, sizeof(struct ipq));
	if ( q == NULL ) {
		err_mem++;
		return NULL;
	}
	ipd->mem += sizeof(struct ipq);

	q->id = iph->id;
	q->saddr = iph->saddr;
	q->daddr = iph->daddr;
	q->protocol = iph->protocol;
	q->next = ipd->hash[hash];
	if ( q->next )
		q->next->pprev = &q->next;
	ipd->hash[hash] = q;
	q->pprev = &ipd->hash[hash];

	return q;
}

/* Find (or create) the ipq for this IP fragment */
static struct ipq *ip_find(struct ipdefrag *ipd,
				const struct pkt_iphdr *iph,
				unsigned int *hash,
				struct _pkt *pkt)
{
	struct ipq *qp;

	*hash = ipq_hashfn(iph->id, iph->saddr,
				iph->daddr, iph->protocol);

	for(qp = ipd->hash[*hash]; qp; qp = qp->next) {
		if ( (qp->id == iph->id) &&
			(qp->saddr == iph->saddr) &&
			(qp->daddr == iph->daddr) &&
			(qp->protocol == iph->protocol) ) {
			return qp;
		}
	}

	qp = ip_frag_create(ipd, *hash, iph);
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

/* Trim down to low memory watermark */
static void ip_evictor(struct ipdefrag *ipd, struct _pkt *pkt, struct ipq *cq)
{
	dmesg(M_DEBUG, "Running the ipfrag evictor! %u(%i) %i",
		ipd->mem, ipd->mem, sizeof(struct ipfrag));
	alert_oom(pkt);
	err_mem++;

	while ( (ipd->mem > mem_lo) ) {
		if ( !ipd->ipq_oldest || (ipd->ipq_oldest == cq) )
			return;
		ipq_kill(ipd, ipd->ipq_oldest);
	}
}

static int check_timeouts(struct ipdefrag *ipd,
				struct _pkt *pkt, struct ipq *qp)
{
	/* Check our timeout */
	if ( !expired(pkt, qp) ) {
		/* We alert if we actually see a fragment
		 * arrive after the timeout because that
		 * is suspicious (read: evasive)
		*/
		alert_timedout(pkt);
		ipq_kill(ipd, qp);
		return 0;
	}

	/* Move qp to head of LRU list */
	if ( qp->next_time)
		qp->next_time->prev_time = qp->prev_time;
	if ( qp->prev_time)
		qp->prev_time->next_time = qp->next_time;
	if ( qp == ipd->ipq_oldest )
		ipd->ipq_oldest = qp->prev_time;
	if ( qp == ipd->ipq_latest )
		ipd->ipq_latest = qp->next_time;
	qp->next_time = ipd->ipq_latest;
	qp->prev_time = NULL;
	if ( !ipd->ipq_oldest )
		ipd->ipq_oldest = qp;
	if ( ipd->ipq_latest )
		ipd->ipq_latest->prev_time = qp;
	ipd->ipq_latest = qp;

	/* Check timeouts on other fragment queues */
	while ( ipd->ipq_oldest ){
		if ( expired(pkt, ipd->ipq_oldest) )
			break;

		/* this can't kill qp from under us because
		 * we already know we haven't timed out */
		ipq_kill(ipd, ipd->ipq_oldest);
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

static void hash_mtf(struct ipdefrag *ipd, unsigned int hash, struct ipq *qp)
{
	/* Move to front heuristic */
	if ( qp->next )
		qp->next->pprev = qp->pprev;
	*qp->pprev = qp->next;
	if ( (qp->next = ipd->hash[hash]) )
		qp->next->pprev = &qp->next;
	ipd->hash[hash] = qp;
	qp->pprev = &ipd->hash[hash];
}

static int queue_fragment(struct ipdefrag *ipd,
				unsigned int hash,
				struct ipq *qp,
				struct _pkt *pkt,
				const struct pkt_iphdr *iph)
{
	struct ipfrag *prev, *next, *me;
	int flags, offset;
	int ihl, end, len;
	int chop = 0;

	if ( !check_timeouts(ipd, pkt, qp) )
		return 0;

	hash_mtf(ipd, hash, qp);

	/* Kill off LRU ipqs, we are OOM */
	if ( ipd->mem > mem_hi )
		ip_evictor(ipd, pkt, qp);

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
		/* FIXME: isn't this a bug? */
		alert_oversize(pkt);
		return 0;
	}

	/* Insert data into fragment chain */
	me = fragstruct_alloc(ipd);
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
			struct ipfrag *free_it=next;

			/* Old fragment is completely overriden
			 * with new one. Drop it */
			next = next->next;
			if ( prev ){
				prev->next = next;
			}else{
				qp->fragments = next;
			}

			qp->meat -= free_it->len;
			fragstruct_free(ipd, free_it);
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
			fragstruct_free(ipd, me);
			return 0;
		}

		ipd->mem += alen;
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

pkt_t _ipfrag_track(flow_state_t s, pkt_t pkt, dcb_t dcb_ptr)
{
	struct ipdefrag *ipd = s;
	const struct pkt_iphdr *iph;
	struct ipfrag_dcb *dcb;
	unsigned int hash;
	struct ipq *q;
	pkt_t ret = NULL;

	dcb = (struct ipfrag_dcb *)dcb_ptr;
	iph = dcb->ip_iph;

	/* Ignore packets with ttl < min_ttl */
	if ( iph->ttl < minttl )
		return ret;

	q = ip_find(ipd, iph, &hash, pkt);
	if ( q == NULL )
		return ret;

	if ( queue_fragment(ipd, hash, q, pkt, iph) ) {
		ret = reassemble(ipd, q, pkt->pkt_source);
		ipq_kill(ipd, q);
	}

	return ret;
}

void _ipfrag_dtor(flow_state_t s)
{
	struct ipdefrag *ipd = s;

	mesg(M_INFO, "ipfrag: %u reassembled packets, "
		"%u reasm errors, %u timeouts",
		reassembled, err_reasm, err_timeout);
	mesg(M_INFO, "ipfrag: %u times out of memory, %uKB still used",
		err_mem, ipd->mem >> 10);

	/* FIXME: memory leak */
	free(s);
}

flow_state_t _ipfrag_ctor(void)
{
	struct ipdefrag *ipd;

	if ( mem_hi <= mem_lo ) {
		mesg(M_ERR, "ipfrag: mem_hi must be bigger than mem_lo");
		return NULL;
	}

	if ( minttl > 255 ) {
		mesg(M_ERR, "ipfrag: minttl must be < 256");
		return NULL;
	}

	ipd = calloc(1, sizeof(*ipd));
	if ( ipd == NULL )
		return NULL;

	mesg(M_INFO, "ipfrag: mem_hi=%u mem_lo=%u minttl=%u timeout=%llus",
		mem_hi, mem_lo, minttl, timeout / TIMESTAMP_HZ);

	if ( timeout < (10 * TIMESTAMP_HZ) ||
		timeout > (120 * TIMESTAMP_HZ) ) {
		mesg(M_WARN, "ipfrag: timeout is unreasonable - "
			"you will be vulnerable to attack!");
	}

	return ipd;
}
