/*
 * This file is part of dotscara
 * Copyright (c) 2004 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
 */
#ifndef _FDCTL_HEADER_INCLUDED_
#define _FDCTL_HEADER_INCLUDED_

int fd_read(int fd, void *buf, size_t *sz, int *eof)
	_nonull(2,3,4) _check_result;
int fd_write(int fd, const void *buf, size_t len)
	_nonull(2) _check_result;
int fd_close(int fd);

int fdctl_block(int fd, int b);
int fdctl_coe(int fd, int coe);

#endif /* _FDCTL_HEADER_INCLUDED_ */
