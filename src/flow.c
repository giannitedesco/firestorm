/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_flow.h>

static struct _flow_tracker *ft_list;

void flow_tracker_add(struct _flow_tracker *ft)
{
	assert(ft != NULL && ft->ft_proto != NULL && ft->ft_label != NULL);
	ft->ft_next = ft_list;
	ft_list = ft;
}

int flow_tracker_foreach(int(*cbfn)(struct _flow_tracker *f, void *priv),
				void *priv)
{
	struct _flow_tracker *ft;
	int ret = 1;

	for(ft = ft_list; ft; ft = ft->ft_next) {
		ret = (*cbfn)(ft, priv);
		if ( ret == 0 )
			return ret;
	}

	return ret;
}
