/*
* This file is part of Firestorm NIDS
* Copyright (c) 2003,2004 Gianni Tedesco
* This program is released under the terms of the GNU GPL version 2
*/

#include <firestorm.h>
#include <ctype.h>

/* Convert a vector string in to an unsigned int */
size_t vtouint(struct ro_vec *v, unsigned int *u)
{
	const uint8_t *ptr, *end;

	for((*u) = 0, ptr = v->v_ptr, end = ptr + v->v_len; ptr < end; ptr++) {
		unsigned int digit = (*ptr) - '0';

		if ( digit >= 10 )
			break;

		(*u) *= 10;
		(*u) += digit;
	}

	return ptr - v->v_ptr;
}

/* Case-insensitive comparison of two vectors */
int vcasecmp(const struct ro_vec *v1, const struct ro_vec *v2)
{
	size_t idx;
	ssize_t ret;

	ret = v1->v_len - v2->v_len;
	if ( 0 == ret ) {
		for(idx = 0; idx < v1->v_len; idx++) {
			ret = tolower(v1->v_ptr[idx]) - tolower(v2->v_ptr[idx]);
			if ( ret )
				break;
		}
	}

	return ret;
}

/* Case-sensitive comparison of two vectors */
int vcmp(const struct ro_vec *v1, const struct ro_vec *v2)
{
	size_t idx;
	ssize_t ret;

	ret = v1->v_len - v2->v_len;
	if ( 0 == ret ) {
		for(idx = 0; idx < v1->v_len; idx++) {
			ret = v1->v_ptr[idx] - v2->v_ptr[idx];
			if ( ret )
				break;
		}
	}

	return ret;
}

/* Case-insensitive comparison of a string and a vector */
int vstrcmp(const struct ro_vec *v1, const char *str)
{
	struct ro_vec v2;

	v2.v_ptr = (void *)str;
	v2.v_len = strlen(str);

	return vcasecmp(v1, &v2);
}
