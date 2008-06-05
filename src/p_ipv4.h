/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _P_IPV4_HEADER_INCLUDED_
#define _P_IPV4_HEADER_INCLUDED_

struct ipfrag_dcb {
	struct _dcb ip_dcb;
	const struct pkt_iphdr *ip_iph;
};

struct ip_dcb {
	struct _dcb ip_dcb;
	const struct pkt_iphdr *ip_iph;
	const struct pkt_ahhdr *ip_ah;
};

/* Keeps each individual fragment */
struct ipfrag {
	struct ipfrag		*next;
	int			len;
	int			offset;
	void			*data;
	unsigned int		free;
	void			*fdata; /* Data to free */
	unsigned int		flen;
};

/* This is an IP session structure */
struct ipq {
	struct ipq *next;
	struct ipq **pprev;
	struct ipq *next_time;
	struct ipq *prev_time;
	
	/* Identify the packet */
	uint32_t saddr;
	uint32_t daddr;
	uint16_t id;
	uint8_t protocol;

#define FIRST_IN 0x2
#define LAST_IN 0x1
	uint8_t last_in;

	/* Linked list of fragments */
	struct ipfrag *fragments;

	/* Total size of all the fragments we have */
	int meat;

	/* Total length of full packet */
	int len;

	/* Stuff we need for reassembly */
	timestamp_t	time;
};

flow_state_t _ipfrag_ctor(void);
void _ipfrag_dtor(flow_state_t s);
void _ipfrag_track(flow_state_t s, struct _pkt *pkt, struct _dcb *dcb);

#endif /* _P_IPV4_HEADER_INCLUDED_ */
