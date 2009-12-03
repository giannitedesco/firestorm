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
	const uint8_t *chr = v->v_ptr;
	size_t i;

	*u = 0;

	for(i=0; i < v->v_len; i++) {
		unsigned int digit = *chr++ - '0';
		if ( digit >= 10 )
			break;

		*u *= 10;
		*u += digit;
	}

	return i;
}

/* Case-insensitive comparison of two vectors */
int vcasecmp(const struct ro_vec *v1, const struct ro_vec *v2)
{
	size_t idx;

	if ( v1->v_len < v2->v_len )
		return -1;
	if ( v1->v_len > v2->v_len )
		return 1;

	for(idx = 0; idx < v1->v_len; idx++) {
		int ret;
		ret = tolower(v1->v_ptr[idx]) - tolower(v2->v_ptr[idx]);
		if ( ret )
			return ret;
	}

	return 0;
}

/* Case-sensitive comparison of two vectors */
int vcmp(const struct ro_vec *v1, const struct ro_vec *v2)
{
	const uint8_t *end1, *end2;
	const uint8_t *p1, *p2;

	end1 = v1->v_ptr + v1->v_len;
	end2 = v2->v_ptr + v2->v_len;

	p1 = v1->v_ptr;
	p2 = v2->v_ptr;

	for(;;) {
		if ( p1 == end1 && p2 == end2 )
			return 0;

		if ( p1 == end1 )
			return -1;

		if ( p2 == end2 )
			return 1;

		if ( *p1 < *p2 )
			return -1;

		if ( *p1 > *p2 )
			return 1;

		p1++; p2++;
	}
	
}

/* Case-insensitive comparison of a string and a vector */
int vstrcmp(const struct ro_vec *v1, const char *str)
{
	struct ro_vec v2;

	v2.v_ptr = (void *)str;
	v2.v_len = strlen(str);

	return vcasecmp(v1, &v2);
}
