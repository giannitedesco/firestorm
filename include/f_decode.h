/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_DECODE_HEADER_INCLUDED_
#define _FIRESTORM_DECODE_HEADER_INCLUDED_

enum {
	NS_DLT, /* pcap DLT_* namespace */
	NS_UNIXPF, /* UNIX PF_* namespace */
	NS_ETHER, /* ethernet namespace: 0x0800 = ip, etc.. */
	NS_INET, /* IPv4 protocol id's, 7 = udp etc.. */
	NS_INET6, /* IPv6 protocol id's */
	NS_USTREAM, /* User stream protocol (any stream protocol) */
	NS_UDGRAM, /* User datagram protocol (not udp per se, but anything) */
	NS_MAX
};

struct _decoder {
	const char *d_label;
	void (*d_decode)(struct _pkt *p);
	struct _proto *d_protos;
	struct _decoder *d_next;
};

struct _ns_entry {
	proto_id_t nse_id;
	struct _decoder *nse_decoder;
};

struct _namespace {
	struct _ns_entry *ns_reg;
	unsigned int ns_num_reg;
	const char *ns_label;
};

struct _proto {
	const struct _ns_entry *p_ns;
	unsigned int p_num_ns;
	proto_ns_t p_namespace;
	struct _proto *p_next;
	const char *p_label;
};

/* Decoders */
void decoder_add(struct _decoder *d);
void decoder_register(struct _decoder *d, proto_ns_t ns, proto_id_t id);

/* Protocols */
void proto_add(struct _decoder *d, struct _proto *p);

/* Decoding */
void decode(struct _source *s, struct _pkt *p);

static inline struct _decoder * _constfn
_ns_entry_search(const struct _ns_entry *p, unsigned int n, proto_id_t id)
{
	while( n ) {
		unsigned int i;

		i = (n / 2);
		if ( id < p[i].nse_id ) {
			n = i;
		}else if ( id > p[i].nse_id ) {
			p = p + (i + 1);
			n = n - (i + 1);
		}else{
			return p[i].nse_decoder;
		}
	}

	return NULL;
}

static inline void _decode_next(pkt_t pkt, struct _proto *p, proto_id_t id)
{
	struct _decoder *d;
	d = _ns_entry_search(p->p_ns, p->p_num_ns, id);
	if ( d != NULL )
		d->d_decode(pkt);
}
#endif /* _FIRESTORM_DECODE_HEADER_INCLUDED_ */
