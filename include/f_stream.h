/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2009 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_STREAM_HEADER_INCLUDED_
#define _FIRESTORM_STREAM_HEADER_INCLUDED_

enum {
	SNS_TCP,
	SNS_HTTP,
	SNS_RFC822,
	SNS_MAX,
};

struct _sdecode {
	ssize_t (*sd_push)(struct _pkt *pkt, struct ro_vec *vec,
				size_t numv, size_t bytes);
	void (*sd_stream_clear)(const struct _dcb *dcb);
	int (*sd_flow_init)(void *priv);
	void (*sd_flow_fini)(void *priv);
	size_t sd_flow_sz;
	size_t sd_max_msg;
	struct _sdecode *sd_next;
	unsigned int sd_idx;
	const char *sd_label;
};

struct _sns_entry {
	proto_id_t nse_id;
	struct _sdecode *nse_sdecode;
};

struct _stream_ns {
	struct _sns_entry *ns_reg;
	unsigned int ns_num_reg;
	const char *ns_label;
};

unsigned int stream_num_sdecode(void);
size_t stream_max_flow_size(proto_ns_t ns);
void sdecode_add(struct _sdecode *sd);
void sdecode_register(struct _sdecode *sd, proto_ns_t ns, proto_id_t id);
_constfn const struct _sdecode *sdecode_find(proto_ns_t ns, proto_id_t id);

ssize_t stream_push_line(struct ro_vec *vec, size_t numv, size_t bytes,
				size_t *bufsz);
#endif /* _FIRESTORM_STREAM_HEADER_INCLUDED_ */
