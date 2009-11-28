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
	SNS_SMTP,
	SNS_POP3,
	SNS_MAX,
};

struct _stream {
	uint8_t *(*s_reasm)(struct _stream *s, size_t bytes);
	void *s_flow;
};

struct _sproto {
	ssize_t (*sp_push)(struct _stream *s, unsigned int chan,
				struct ro_vec *vec, size_t numv, size_t bytes);
	size_t sp_flow_sz;
	struct _sproto *sp_next;
	unsigned int sp_idx;
	const char *sp_label;
};

struct _sns_entry {
	proto_id_t nse_id;
	struct _sproto *nse_sproto;
};

struct _stream_ns {
	struct _sns_entry *ns_reg;
	unsigned int ns_num_reg;
	const char *ns_label;
};

size_t stream_max_flow_size(proto_ns_t ns);
unsigned int stream_num_sproto(void);
void sproto_add(struct _sproto *sp);
void sproto_register(struct _sproto *sp, proto_ns_t ns, proto_id_t id);
_constfn const struct _sproto *sproto_find(proto_ns_t ns, proto_id_t id);

#endif /* _FIRESTORM_STREAM_HEADER_INCLUDED_ */
