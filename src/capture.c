/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_capture.h>

void _source_free(struct _source *s)
{
	if ( s ) {
		assert(s->s_capdev != NULL);
		s->s_capdev->c_dtor(s);
	}
}
