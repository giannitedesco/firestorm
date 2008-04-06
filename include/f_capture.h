#ifndef _FIRESTORM_CAPTURE_HEADER_INCLUDED_
#define _FIRESTORM_CAPTURE_HEADER_INCLUDED_

typedef struct _source *source_t;
typedef struct _capdev *capdev_t;

source_t capture_tcpdump_open(const char *fn);

#endif /* _FIRESTORM_CAPTURE_HEADER_INCLUDED_ */
