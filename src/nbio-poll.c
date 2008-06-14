/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2004 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
 *
 * Poll based eventloop
 */
#include <firestorm.h>
#include <nbio.h>
#include <sys/poll.h>

struct poll_priv {
	int max_pfd, num_pfd;
	struct pollfd *pfd;
};

static int upsize_pfdset(struct poll_priv *p)
{
	unsigned int max;
	struct pollfd *new;

	max = p->max_pfd + 8;

	new = realloc(p->pfd, max * sizeof(*p->pfd));
	if ( new == NULL )
		return 0;

	p->max_pfd = max;
	p->pfd = new;
	return 1;
}

static int poll_init(struct iothread *t)
{
	struct poll_priv *p;

	p = calloc(1, sizeof(*p));
	if ( p == NULL ) {
		return 0;
	}

	if ( !upsize_pfdset(p) ) {
		free(p);
		return 0;
	}

	t->priv.ptr = p;

	return 1;
}

static void poll_fini(struct iothread *t)
{
	struct poll_priv *p = t->priv.ptr;
	free(p->pfd);
	free(p);
}

static void poll_pump(struct iothread *t, int mto)
{
	struct poll_priv *p = t->priv.ptr;
	struct nbio *n, *tmp;
	int ret;

	ret = poll(p->pfd, p->num_pfd, mto);
	if ( ret < 0 )
		return;

	p->num_pfd = 0;

	list_for_each_entry_safe(n, tmp, &t->inactive, list) {
		struct pollfd *pfd;

		if ( n->ev_priv.poll < 0 )
			continue;

		pfd = &p->pfd[n->ev_priv.poll];

		if ( pfd->revents == 0 ) {
			p->pfd[p->num_pfd].fd = pfd->fd;
			p->pfd[p->num_pfd].events = pfd->events;
			p->num_pfd++;
			continue;
		}

		n->flags = 0;

		if ( pfd->revents & (POLLIN|POLLHUP) )
			n->flags |= NBIO_READ;
		if ( pfd->revents & POLLOUT )
			n->flags |= NBIO_WRITE;
		if ( pfd->revents & POLLERR )
			n->flags |= NBIO_ERROR;

		n->ev_priv.poll = -1;

		list_move_tail(&n->list, &t->active);
	}
}

static void poll_inactive(struct iothread *t, struct nbio *n)
{
	struct poll_priv *p = t->priv.ptr;
	struct pollfd *pfd;

	if ( p->num_pfd >= p->max_pfd ) {
		if ( !upsize_pfdset(p) )
			return;
	}

	pfd = &p->pfd[p->num_pfd];
	pfd->fd = n->fd;
	pfd->events = POLLERR|POLLHUP;
	if ( n->mask & NBIO_READ )
		pfd->events |= POLLIN;
	if ( n->mask & NBIO_WRITE )
		pfd->events |= POLLOUT;
	n->ev_priv.poll = p->num_pfd++;
}

static void poll_active(struct iothread *t, struct nbio *n)
{
	n->ev_priv.poll = -1;
}

static struct eventloop eventloop_poll = {
	.name = "poll",
	.init = poll_init,
	.fini = poll_fini,
	.inactive = poll_inactive,
	.active = poll_active,
	.pump = poll_pump,
};

void _eventloop_poll_ctor(void)
{
	eventloop_add(&eventloop_poll);
}
