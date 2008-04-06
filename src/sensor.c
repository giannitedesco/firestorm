/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_capture.h>

int main(int argc, char **argv)
{
	source_t src;

	mesg(M_INFO,"Firestorm NIDS v0.6.0");
	mesg(M_INFO,"Copyright (c) 2002-2008 Gianni Tedesco");
	mesg(M_INFO,"This program is free software; released under "
		"the GNU GPL v3 (see: COPYING)");

	src = capture_tcpdump_open("./test.cap");
	assert(src != NULL);

	mesg(M_INFO, "Firestorm exiting normally");
	return EXIT_SUCCESS;
}
