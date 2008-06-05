/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_HEADER_INCLUDED_
#define _FIRESTORM_HEADER_INCLUDED_

#if HAVE_CONFIG_H
#include "config.h"
#endif

/* Standard C99 stuff */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include <list.h>

#include <f_compiler.h>
#include <f_time.h>
#include <f_os.h>

typedef struct _pkt *pkt_t;

typedef struct _source *source_t;
typedef struct _capdev *capdev_t;

typedef struct _pipeline *pipeline_t;

typedef struct _decoder *decoder_t;
typedef struct _proto *proto_t;
typedef struct _dcb *dcb_t;
typedef unsigned int proto_ns_t;
typedef unsigned int proto_id_t;

typedef struct _flow_tracker *flow_tracker_t;
typedef void *flow_state_t;

typedef uint8_t mesg_code_t;

/* Message codes */
#define M_UNSET	0 /* Unclassified */
#define M_DEBUG	1 /* For developers */
#define M_INFO	2 /* Informational notices */
#define M_WARN	3 /* We can work around this, but you should know */
#define M_ERR	4 /* We can't do something you asked for */
#define M_CRIT	5 /* Service/data is lost */
#define M_MAX	6
#define M_LIMIT 0x80 /* Ratelimit this message */

/* --- Global firestorm stuff */
void mesg(mesg_code_t code, const char *fmt, ...) _printf(2,3);
void hex_dump(const uint8_t *tmp, size_t len, size_t llen);

/* --- Data-source plugins */
source_t capture_tcpdump_open(const char *fn);

/* --- Decode API */
void decode_init(void);
decoder_t decoder_get(proto_ns_t ns, proto_id_t id);
const char *decoder_label(decoder_t l);

/* --- Pipelines: the capture / decode / analyze mainloop */
pipeline_t pipeline_new(void) _malloc;
void pipeline_free(pipeline_t p);
int pipeline_add_source(pipeline_t p, source_t s);
int pipeline_go(pipeline_t p);

#endif /* _FIRESTORM_HEADER_INCLUDED_ */
