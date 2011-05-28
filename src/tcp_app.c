/* Copyright (c) Gianni Tedesco 2010
 * Author: Gianni Tedesco (gianni at scaramanga dot co dot uk)
*/
#include <firestorm.h>
#include <f_packet.h>
#include <f_decode.h>
#include <list.h>
#include <p_tcp.h>
#include <pkt/tcp.h>
#include "tcpip.h"

#define NAMESPACE_ALLOC_CHUNK	(1<<3)
#define NAMESPACE_ALLOC_MASK	(NAMESPACE_ALLOC_CHUNK-1)

struct dpe {
	uint16_t dport;
	struct tcp_app *app;
};

static struct dpe *dports;
static unsigned int num_dports;
static struct tcp_app *apps;

void tcp_app_register(struct tcp_app *app)
{
	struct _proto *p;

	assert(NULL == app->a_next);
	assert(NULL != app->a_label);
	assert(0 == app->a_max_dcb);

	for(p = app->a_decode->d_protos; p; p = p->p_next)
		if ( app->a_max_dcb < p->p_dcb_sz )
			app->a_max_dcb = p->p_dcb_sz;

	app->a_next = apps;
	apps = app;
}

size_t _tcp_app_max_dcb(void)
{
	struct tcp_app *app;
	size_t dcb = 0;

	for(app = apps; app; app = app->a_next)
		if ( dcb < app->a_max_dcb )
			dcb = app->a_max_dcb;

	return dcb + sizeof(struct tcpstream_dcb);
}

static int dp_assure(void)
{
	static void *new;

	if ( num_dports & NAMESPACE_ALLOC_MASK )
		return 1;

	new = realloc(dports,
			sizeof(*dports) *
			(num_dports + NAMESPACE_ALLOC_CHUNK));
	if ( new == NULL )
		return 0;

	dports = new;
	return 1;
}

static int dp_cmp(const void *A, const void *B)
{
	const struct dpe *a = A, *b = B;
	return a->dport - b->dport;
}

void tcp_app_register_dport(struct tcp_app *app, uint16_t dport)
{
	if ( !dp_assure() ) {
		assert(dp_assure());
		return;
	}

	dports[num_dports].dport = htobe16(dport);
	dports[num_dports].app = app;
	num_dports++;

	qsort(dports, num_dports, sizeof(*dports), dp_cmp);
}

struct tcp_app *_tcp_app_find_by_dport(uint16_t dport)
{
	unsigned int n;
	struct dpe *p;

	for(p = dports, n = num_dports; n; ) {
		unsigned int i;

		i = (n / 2);
		if ( dport < p[i].dport ) {
			n = i;
		}else if ( dport > p[i].dport ) {
			p = p + (i + 1);
			n = n - (i + 1);
		}else{
			return p[i].app;
		}
	}

	return NULL;
}
