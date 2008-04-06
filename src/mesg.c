/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2003,2004 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2 or 3
*/
#include <firestorm.h>

#include <stdio.h>
#include <stdarg.h>

static char *abuf;
static size_t abuflen;

/* Backend */
void _mesg(mesg_code_t code, const char *str, size_t len) _nonull(2);

/* Print out a firestorm internal system log message */
void mesg(mesg_code_t code, const char *fmt, ...)
{
	int len;
	va_list va;
	char *new;

	if ( code & M_LIMIT ) {
		/* TODO: Ratelimit */
	}

	code &= ~M_LIMIT;

again:
	va_start(va, fmt);

	len = vsnprintf(abuf, abuflen, fmt, va);
	if ( len < 0 ) /* bug in old glibc */
		len = 0;
	if ( (size_t)len < abuflen )
		goto done;

	new = realloc(abuf, len + 1);
	if ( new == NULL )
		goto done;

	abuf = new;
	abuflen = len + 1;
	goto again;

done:
	_mesg(code, abuf, (size_t)len);
	va_end(va);
}
