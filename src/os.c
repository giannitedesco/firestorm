/*
* This file is part of Firestorm NIDS
* Copyright (c) 2003 Gianni Tedesco
* Released under the terms of the GNU GPL version 2
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <firestorm.h>

int _public os_errno(void)
{
	return errno;
}

const char _public *os_error(int e)
{
	return strerror(e);
}

const char _public *os_err(void)
{
	return strerror(errno);
}

const char _public *os_err2(const char *def)
{
	if ( def == NULL )
		def = "Internal Error";
	return (errno ? strerror(errno) : def);
}
