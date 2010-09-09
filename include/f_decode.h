/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_DECODE_HEADER_INCLUDED_
#define _FIRESTORM_DECODE_HEADER_INCLUDED_

#define DECODE_DEFAULT_MIN_LAYERS	8

enum {
	NS_DLT, /* pcap DLT_* namespace */
	NS_UNIXPF, /* UNIX PF_* namespace */
	NS_ETHER, /* ethernet namespace: 0x0800 = ip, etc.. */
	NS_INET, /* IPv4 protocol id's, 7 = udp etc.. */
	NS_INET6, /* IPv6 protocol id's */
	NS_IPX, /* Novell Netware's IPX */
	NS_CISCO, /* Cisco SNAP id's */
	NS_APPLE, /* Apple SNAP id's */
	NS_MAX,
};

struct _decoder {
	unsigned int d_idx;
	void (*d_decode)(struct _pkt *p);
	int (*d_flow_ctor)(void);
	void (*d_flow_dtor)(void);
	struct _proto *d_protos;
	struct _decoder *d_next;
	const char *d_label;
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
	unsigned int p_idx;
	struct _proto *p_next;
	struct _decoder *p_owner;
	size_t p_dcb_sz; /* max dcb size */
	void (*p_flowtrack)(pkt_t pkt, dcb_t dcb);
	const char *p_label;
};

struct _dcb {
	struct _proto *dcb_proto;
	struct _dcb *dcb_next;
};

/* ===[ Front end API: decoding ]=== */
unsigned int decode_num_protocols(void);
unsigned int decode_num_decoders(void);
size_t decode_max_dcb_size(void);
int decode_foreach_protocol(int(*cbfn)(proto_t p, void *priv), void *priv)
				_nonull(1);
int decode_foreach_decoder(int(*cbfn)(decoder_t, void *priv), void *priv)
				_nonull(1);

/* ===[ Backend API: for protocol/decoder plugins ]=== */
void decoder_add(struct _decoder *d);
void decoder_register(struct _decoder *d, proto_ns_t ns, proto_id_t id);
void proto_add(struct _decoder *d, struct _proto *p) _nonull(2);
void decode_next(pkt_t pkt, proto_ns_t ns, proto_id_t id);
size_t decode_dcb_len(struct _dcb *dcb);
struct _dcb *decode_layer(pkt_t pkt, struct _proto *p);
struct _dcb *decode_layer0(pkt_t pkt, struct _proto *p);
struct _dcb *decode_layerv(pkt_t pkt, struct _proto *p, size_t sz);
struct _dcb *decode_layerv0(pkt_t pkt, struct _proto *p, size_t sz);

#endif /* _FIRESTORM_DECODE_HEADER_INCLUDED_ */
