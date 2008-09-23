/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_packet.h>
#include <mpool.h>

static struct mpool pkt_pool;

static void __attribute__((constructor)) _ctor(void)
{
	mpool_init(&pkt_pool, sizeof(struct _pkt), 0);
}

static void __attribute__((destructor)) _dtor(void)
{
	mpool_fini(&pkt_pool);
}

pkt_t pkt_alloc(void)
{
	return mpool_alloc0(&pkt_pool);
}

void pkt_free(pkt_t pkt)
{
	if ( pkt && pkt->pkt_dtor )
		pkt->pkt_dtor(pkt);

	mpool_free(&pkt_pool, pkt);
}
