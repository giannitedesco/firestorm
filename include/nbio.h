/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2004 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
*/
#ifndef _NBIO_HEADER_INCLUDED_
#define _NBIO_HEADER_INCLUDED_

/* Represents a given fd */
struct nbio {
	int fd;
#define NBIO_READ	(1<<0)
#define NBIO_WRITE	(1<<1)
#define NBIO_ERROR	(1<<2)
#define NBIO_WAIT	(NBIO_READ|NBIO_WRITE|NBIO_ERROR)
	unsigned short mask, flags;
	struct nbio_ops *ops;
	struct list_head list;
	union {
		int poll;
		void *ptr;
	}ev_priv;
};

/* Represents all the I/Os for a given thread */
struct iothread {
	struct list_head inactive;
	struct list_head active;
	struct eventloop *plugin;
	union {
		int epoll;
		void *ptr;
	}priv;
	struct list_head deleted;
};

struct nbio_ops {
	void (*read)(struct iothread *t, struct nbio *n);
	void (*write)(struct iothread *t, struct nbio *n);
	void (*dtor)(struct iothread *t, struct nbio *n);
};

/* nbio API */
void nbio_add(struct iothread *, struct nbio *, unsigned short) _nonull(1,2);
void nbio_del(struct iothread *, struct nbio *) _nonull(1,2);
void nbio_pump(struct iothread *) _nonull(1);
void nbio_fini(struct iothread *) _nonull(1);
int nbio_init(struct iothread *, const char *plugin) _nonull(1) _check_result;
void nbio_inactive(struct iothread *, struct nbio *) _nonull(1,2);
void nbio_set_wait(struct iothread *, struct nbio *, unsigned short)
		_nonull(1,2);
unsigned short nbio_get_wait(struct nbio *io) _nonull(1);

/* eventloop plugin API */
struct eventloop {
	const char *name;
	int (*init)(struct iothread *);
	void (*fini)(struct iothread *);
	void (*pump)(struct iothread *);
	void (*inactive)(struct iothread *, struct nbio *);
	void (*active)(struct iothread *, struct nbio *);
	struct eventloop *next;
};

void eventloop_add(struct eventloop *e) _nonull(1);
struct eventloop *eventloop_find(const char *name) _nonull(1) _check_result;

#endif /* _NBIO_HEADER_INCLUDED_ */
