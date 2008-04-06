/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_CAPTURE_HEADER_INCLUDED_
#define _FIRESTORM_CAPTURE_HEADER_INCLUDED_

typedef struct _source *source_t;
typedef struct _capdev *capdev_t;
typedef struct _pipeline *pipeline_t;

/* Open a tcpdump file */
source_t capture_tcpdump_open(const char *fn);

/* Capture / decode / analyze mainloop */
pipeline_t pipeline_new(void) _malloc;
void pipeline_free(pipeline_t p);
int pipeline_add_source(pipeline_t p, source_t s);
int pipeline_go(pipeline_t p);

#endif /* _FIRESTORM_CAPTURE_HEADER_INCLUDED_ */
