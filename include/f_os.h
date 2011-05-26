/*
 * This file is part of dotscara
 * Copyright (c) 2003 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
 */
#ifndef _FIRESTORM_OS_HEADER_INCLUDED_
#define _FIRESTORM_OS_HEADER_INCLUDED_

int os_errno(void);
const char *os_error(int);
const char *os_err(void);
const char *os_err2(const char *);

/* Byte-swapping macros. Note that constant versions must actually be passed
 * literals as arguments! This is due to pre-processor badness. You have been
 * warned!
 */
#define const_bswap16(x) \
	((uint16_t)( \
		(((uint16_t)(x) & (uint16_t)0x00ffU) << 8) | \
	 	(((uint16_t)(x) & (uint16_t)0xff00U) >> 8)))

#define const_bswap32(x) \
	((uint32_t)( \
		(((uint32_t)(x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(x) & (uint32_t)0xff000000UL) >> 24)))

#if __BYTE_ORDER == __BIG_ENDIAN
#define const_le32(x) const_bswap32(x)
#define const_le16(x) const_bswap16(x)
#define const_be32(x) (x)
#define const_be16(x) (x)
#define sys_bswap16(x) le16toh(x)
#define sys_bswap32(x) le32toh(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define const_le32(x) (x)
#define const_le16(x) (x)
#define const_be32(x) const_bswap32(x)
#define const_be16(x) const_bswap16(x)
#define sys_bswap16(x) be16toh(x)
#define sys_bswap32(x) be32toh(x)
#else
#error "What in hells name?!"
#endif

#endif /* _FIRESTORM_OS_HEADER_INCLUDED_ */
