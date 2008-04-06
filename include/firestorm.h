/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/
#ifndef _FIRESTORM_HEADER_INCLUDED_
#define _FIRESTORM_HEADER_INCLUDED_

#if HAVE_CONFIG_H
#include "config.h"
#endif

/* Standard C99 stuff */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include <list.h>

#include <f_compiler.h>
#include <f_time.h>
#include <f_os.h>

typedef struct _pkt *pkt_t;

typedef uint8_t mesg_code_t;
#define M_UNSET	0 /* Unclassified */
#define M_DEBUG	1 /* For developers */
#define M_INFO	2 /* Informational notices */
#define M_WARN	3 /* We can work around this, but you should know */
#define M_ERR	4 /* We can't do something you asked for */
#define M_CRIT	5 /* Service/data is lost */
#define M_MAX	6
#define M_LIMIT 0x80 /* Ratelimit this message */

void mesg(mesg_code_t code, const char *fmt, ...) _printf(2,3);

#endif /* _FIRESTORM_HEADER_INCLUDED_ */
