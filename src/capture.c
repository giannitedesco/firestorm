/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_capture.h>

void _source_new(struct _source *s, const struct _capdev *c, const char *label)
{
	assert(s != NULL && c != NULL && label != NULL);
	s->s_io.fd = -1;
	s->s_io.ops = NULL;
	s->s_capdev = c;
	s->s_name = label;
	INIT_LIST_HEAD(&s->s_list);
}

void source_free(source_t s)
{
	if ( s ) {
		assert(s->s_capdev != NULL);
		list_del(&s->s_list);
		s->s_capdev->c_dtor(s);
	}
}
