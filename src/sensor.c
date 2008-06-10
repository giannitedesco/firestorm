/*
 * This file is part of Firestorm NIDS.
 * Copyright (c) 2008 Gianni Tedesco <gianni@scaramanga.co.uk>
 * Released under the terms of the GNU GPL version 3
*/

#include <firestorm.h>
#include <f_capture.h>
#include <memchunk.h>

int main(int argc, char **argv)
{
	source_t src;
	pipeline_t p;
	memchunk_t m;

	mesg(M_INFO,"Firestorm NIDS v0.6.0");
	mesg(M_INFO,"Copyright (c) 2002-2008 Gianni Tedesco");
	mesg(M_INFO,"This program is free software; released under "
		"the GNU GPL v3 (see: COPYING)");

	decode_init();

	m = memchunk_init(32768);
	if ( m == NULL ) {
		mesg(M_ERR, "memchunk_new: %s", os_err2(NULL));
		return EXIT_FAILURE;
	}

	if ( argc > 1 ) {
		src = capture_tcpdump_open(argv[1]);
	}else{
		src = capture_tcpdump_open("./test.cap");
	}
	if ( src == NULL )
		return EXIT_FAILURE;

	p = pipeline_new();
	assert(p != NULL);

	if ( !pipeline_add_source(p, src) )
		return EXIT_FAILURE;

	pipeline_go(p);

	pipeline_free(p);

	memchunk_fini(m);

	mesg(M_INFO, "Firestorm exiting normally");
	return EXIT_SUCCESS;
}
