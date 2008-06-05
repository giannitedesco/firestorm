/*
 * This file is part of Firestorm NIDS
 * Copyright (c) Gianni Tedesco 2002,2003,2004.
 * This program is released under the terms of the GNU GPL version 2
 */
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_flow.h>
#include <pkt/ip.h>
#include "p_ipv4.h"

#if 1
#define dmesg mesg
#else
#define dmesg(x...) do{}while(0);
#endif

/*
 * IP Defragmentation for firestorm
 * ================================
 *
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
 *  o Audit and document
 *  o Per-ip accounting (timeouts/etc..)
 *  o Use more efficient search to insert fragments
 *  o Coalesce fragments in incomplete packets (?)
 *  o Detect ICMP_TIME_EXCEEDED/ICMP_EXC_FRAGTIME (??)
 */

#define IPHASH (1<<7) /* Must be a power of two */
struct ipdefrag {
	struct ipq *ipq_latest;
	struct ipq *ipq_oldest;

	unsigned int mem;

	struct ipq *hash[IPHASH]; /* IP fragment hash table */

	/* config: high and low memory water marks */
	unsigned int mem_hi;
	unsigned int mem_lo;

	/* config: Timeout (in seconds) */
	timestamp_t timeout;

	/* config: Don't decode fragments with too low ttl */
	unsigned int minttl;

	/* Statistics */
	unsigned int err_reasm;
	unsigned int err_mem;
	unsigned int err_timeout;
	unsigned int reassembled;
};

/* Reassembly */
static char *reasm_buf;
static unsigned int reasm_len;

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
static void alert_truncated(struct _pkt *p)
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

/* Reassemble a complete set of fragments, decode the
 * new packet, and send it back through the preprocessor
 * list, we won't touch it next time round */
static void reassemble(struct ipdefrag *ipd, struct ipq *qp, struct _pkt *pkt)
{
	struct ipfrag *f;
	struct pkt_iphdr *iph;
	unsigned int olen = qp->len;
	unsigned int len = 0;
	char *buf;
	char *tmp;

	/* Kill oversize packets */
	if ( olen > 0xffff ) {
		ipd->err_reasm++;
		return;
	}

	if ( !qp->fragments ) {
		ipd->err_reasm++;
		return;
	}

	iph = qp->fragments->fdata;
	olen += iph->ihl << 2;

	/* Allocate the frankenpacket buffer */
	if ( olen > reasm_len ) {
		tmp = realloc(reasm_buf, olen);
		if ( tmp == NULL ) {
			olen = reasm_len;
			dmesg(M_DEBUG, "ipfrag: reassemble error!");
			ipd->err_reasm++;
			return;
		}else{
			reasm_buf = tmp;
			reasm_len = qp->len;
		}
	}

	/* Copy all the fragments in to the new buffer */
	dmesg(M_DEBUG, "Reassemble: %u bytes", olen);
	buf = reasm_buf;

	/* Do the header */
	dmesg(M_DEBUG, " * %u byte header", iph->ihl << 2);
	memcpy(buf, qp->fragments->fdata, iph->ihl << 2);
	buf += iph->ihl << 2;
	len += iph->ihl << 2;

	for(f=qp->fragments; f; f=f->next) {
		dmesg(M_DEBUG, " * %u bytes @ %u", f->len, f->offset);
		memcpy(buf, f->data, f->len);
		buf += f->len;
		len += f->len;
		if ( len >= olen ) break;
	}
	dmesg(M_DEBUG, ".");

#if 0
	/* Build the packet */
	packet_reinject_prepare(&ipfr, pkt);

	/* Fill in the timestamp (time of last packet seen for this frag) */
	ipfr.time = qp->time;
	ipfr.len = len;
	ipfr.caplen = len;
	ipfr.llen = 0;
	ipfr.layer[0].proto = &ipv4_p;
	ipfr.layer[0].h.raw = reasm_buf;
	ipfr.layer[0].flags = FLAG_IP_REASM | FLAG_IP_CSUM;
	ipfr.layer[0].session = NULL;
	ipfr.base = reasm_buf;
	ipfr.end = ipfr.base + olen;

	/* Fixup the IP header */
	ipfr.layer[0].h.ip->frag_off = 0;
	ipfr.layer[0].h.ip->tot_len = ntohs(len);
	ipfrag_csum(ipfr.layer[0].h.ip);

	/* Inject the packet back in to the flow */
	ipfrag_reassembled++;
	ipfr.layer[0].proto->decode(&ipfr);
#endif

	return;
}

static struct ipq *ip_frag_create(struct ipdefrag *ipd, unsigned int hash,
					const struct pkt_iphdr *iph)
{
	struct ipq *q;

	q = calloc(1, sizeof(struct ipq));
	if ( q == NULL ) {
		ipd->err_mem++;
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
static int expired(struct ipdefrag *ipd, struct _pkt *pkt, struct ipq *qp)
{
	if ( time_after(pkt->pkt_ts, qp->time + ipd->timeout) ) {
		ipd->err_timeout++;
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
	ipd->err_mem++;

	while ( (ipd->mem > ipd->mem_lo) ) {
		if ( !ipd->ipq_oldest || (ipd->ipq_oldest == cq) )
			return;
		ipq_kill(ipd, ipd->ipq_oldest);
	}
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
	int chop=0;

	/* Move to head of LRU list */
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

	/* Check our timeout */
	if ( !expired(ipd, pkt, qp) ) {
		/* We alert if we actually see a fragment
		 * arrive after the timeout because that
		 * is suspicious (read: evasive) */
		alert_timedout(pkt);
		ipq_kill(ipd, qp);
		return 1;
	}

	/* Check other timeouts */
	while ( ipd->ipq_oldest ){
	       	if ( expired(ipd, pkt, ipd->ipq_oldest) )
			break;

		/* this can't kill qp from under us because
		 * we already know we haven't timed out */
		ipq_kill(ipd, ipd->ipq_oldest);
	}

	/* Move to front heuristic */
	if ( qp->next )
		qp->next->pprev = qp->pprev;
	*qp->pprev = qp->next;
	if ( (qp->next = ipd->hash[hash]) )
		qp->next->pprev = &qp->next;
	ipd->hash[hash] = qp;
	qp->pprev = &ipd->hash[hash];

	/* The time for the reassembled packet is equal
	 * to the time of the last packet recieved. This
	 * makes things sane in the sense that time won't
	 * be seen to be going backwards by the higher layers!
	 */
	qp->time = pkt->pkt_ts;

	/* Kill off LRU ipqs, we are OOM */
	if ( ipd->mem > ipd->mem_hi )
		ip_evictor(ipd, pkt, qp);

	/* Now we can get on with queueing the packet.. */
	ihl = iph->ihl << 2;
	len = sys_be16(iph->tot_len);

	if ( ((uint8_t *)iph) + len > pkt->pkt_end ) {
		alert_truncated(pkt);
		return 1;
	}

	offset = sys_be16(iph->frag_off);
	flags = offset & ~IP_OFFMASK;
	offset &= IP_OFFMASK;
	offset <<= 3; /* 8 byte granularity */

	end = offset + len - ihl;

	if ( (flags & IP_MF) == 0 ) {
		if ( (end < qp->len) ||
			((qp->last_in & LAST_IN) && (end != qp->len))) {
			alert_teardrop(pkt);
			return 1;
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
				return 1;
			}
			qp->len = end;
		}
	}

	if ( end == offset ) {
		alert_attack(pkt);
		return 1;
	}

	/* Don't bother wasting any more resources
	 * when we know the packet is oversize (invalid) */
	if ( qp->len > 0xffff ) {
		/* FIXME: isn't this a bug? */
		alert_oversize(pkt);
		return 1;
	}

	/* Insert data into fragment chain */
	me = fragstruct_alloc(ipd);
	if ( me == NULL )
		return 1;

	/* Find out where to insert this fragment in the list */
	for(prev=NULL, next=qp->fragments; next; next=next->next) {
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
				return 1;
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

	/* XXX: IP defragmentation can be zerocopy */
	if ( 1 ) {
		unsigned int alen = me->len;

		if ( !offset )
			alen += ihl;

		me->fdata = malloc(alen);
		if ( me->fdata == NULL ) {
			fragstruct_free(ipd, me);
			return 1;
		}

		ipd->mem += alen;
		memcpy(me->fdata, ((char *)iph) + chop, alen);
		me->free = 1;
		me->flen = alen;
	}else {
		me->fdata = ((void *)iph) + chop;
		me->free = 0;
	}

	me->data = me->fdata;

	/* FIXME: looks wrong */
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

	return 1;
}

void _ipfrag_track(flow_state_t s, struct _pkt *pkt, struct _dcb *dcb_ptr)
{
	struct ipdefrag *ipd = s;
	const struct pkt_iphdr *iph;
	struct ipfrag_dcb *dcb;
	unsigned int hash;
	struct ipq *q;

	dcb = (struct ipfrag_dcb *)dcb_ptr;
	iph = dcb->ip_iph;

	/* Ignore packets with ttl < min_ttl */
	if ( iph->ttl < ipd->minttl )
		return;

	q = ip_find(ipd, iph, &hash, pkt);
	if ( q == NULL )
		return;

	if ( !queue_fragment(ipd, hash, q, pkt, iph) )
		return;

	if ( q->last_in == (FIRST_IN|LAST_IN) &&
		q->meat == q->len ) {
		reassemble(ipd, q, pkt);
	}
}

void _ipfrag_dtor(flow_state_t s)
{
	struct ipdefrag *ipd = s;

	mesg(M_INFO, "ipfrag: %u reassembled packets, "
	       "%u reasm errors, %u timeouts",
		ipd->reassembled,
		ipd->err_reasm,
		ipd->err_timeout);
	mesg(M_INFO, "ipfrag: %u times out of memory, %uKB still used",
		ipd->err_mem,
		ipd->mem >> 10);

	/* FIXME: memory leak */
	free(s);
}

flow_state_t _ipfrag_ctor(void)
{
	struct ipdefrag *ipd;

	ipd = calloc(1, sizeof(*ipd));
	if ( ipd != NULL ) {
		ipd->mem_hi = 4 << 20;
		ipd->mem_lo = 3 << 20;
		ipd->minttl = 1;
		ipd->timeout = 30 * TIMESTAMP_HZ;

		mesg(M_INFO, "ipfrag: mem_hi=%u mem_lo=%u "
			"minttl=%u timeout=%llus",
			ipd->mem_hi, ipd->mem_lo,
			ipd->minttl, ipd->timeout / TIMESTAMP_HZ);

	}
#if 0
	if ( ipd->mem_hi <= ipd->mem_lo ) {
		mesg(M_ERR, "ipfrag: mem_hi must be bigger than mem_lo");
		return 0;
	}

	if ( ipfrag_minttl > 255 ) {
		mesg(M_ERR, "ipfrag: minttl must be < 256");
		return 0;
	}

	if (ipd->timeout < 10 || ipd->timeout > 120) {
		mesg(M_WARN, "ipfrag: timeout is unreasonable - "
			"you will be vulnerable to attack!");
	}

#endif
	return ipd;
}
