/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2003,2004 Gianni Tedesco
 * This program is released under the terms of the GNU GPL version 2
 *
 * mesg backend for the sensor, we just print to stdout.
 */
#include <firestorm.h>

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static char *code_str[] = {
	"undefined",
	"debug",
	"info",
	"warning",
	"error",
	"critical",
};

/* Print out a firestorm internal system log message */
void _mesg(mesg_code_t code, const char *str, size_t len);
void _mesg(mesg_code_t code, const char *str, size_t len)
{
	static char tbuf[64];
	struct timeval tv;
	struct tm *tm;
	FILE *f;

	if ( code > M_MAX )
		code = 0;

	if ( code >= M_WARN )
		f = stderr;
	else
		f = stdout;

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);
	//strftime(tbuf, sizeof(tbuf), "%Y-%M-%d %H:%M:%S", tm);
	strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm);

	//printf("%s: %s: %s\n", tbuf, code_str[code], str);
	printf("%s: %s\n", code_str[code], str);

	fflush(stdout);
}
