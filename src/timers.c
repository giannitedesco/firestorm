/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2004 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
 *
 * TODO:
 *  o Use POSIX high res timers for time_gettime()
 *  o Port OS specific parts and provide generic replacements where
 *    possible
*/

#include <firestorm.h>
#include <f_time.h>

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

timestamp_t time_gettime(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return time_from_timeval(&tv);
}

timestamp_t time_getvtime(void)
{
#if HAVE_GETRUSAGE
	struct rusage r;
	getrusage(RUSAGE_SELF, &r);
	return time_from_timeval(&r.ru_utime);
#else
	return 0;
#endif
}

static inline time_t do_time_to_time_t(timestamp_t t)
{
	return (time_t)(t / TIMESTAMP_HZ);
}

time_t time_to_time_t(timestamp_t t)
{
	return do_time_to_time_t(t);
}

void time_to_local(timestamp_t t, struct tm *tm)
{
	time_t tt = do_time_to_time_t(t);
	*tm = *gmtime(&tt);
}

void time_to_gmt(timestamp_t t, struct tm *tm)
{
	time_t tt = do_time_to_time_t(t);
	*tm = *localtime(&tt);
}

void time_to_timeval(timestamp_t t, struct timeval *tv)
{
	tv->tv_sec = t / TIMESTAMP_HZ;
	tv->tv_usec = (t % TIMESTAMP_HZ) / TIMESTAMP_MHZ;
}

/* Using euclids greatest common divisor */
timestamp_t time_gcd(timestamp_t n, timestamp_t d)
{
	timestamp_t r;

	if ( n < d ) {
		timestamp_t tmp;
		tmp = d;
		d = n;
		n = tmp;
	}

	if ( n == 0 )
		return d;

	while ( d > 0 ) {
		r = n % d;
		n = d;
		d = r;
	}

	return n;
}
