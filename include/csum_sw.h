#ifndef _CSUM_SW_H
#define _CSUM_SW_H

static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static inline unsigned int do_csum_sw(const unsigned char *buff, int len)
{
	int odd, count;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				count--;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (count);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#if __BYTE_ORDER == __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

static inline uint32_t csum_tcpudp_nofold(uint32_t saddr, uint32_t daddr,
			unsigned short len,
			unsigned short proto,
			uint32_t sum)
{
	unsigned long long s = sum;

	s += saddr;
	s += daddr;
#if __BYTE_ORDER == __BIG_ENDIAN
	s += proto + len;
#else
	s += (proto + len) << 8;
#endif
	s += (s >> 32);
	return (uint32_t)s;
}

static inline uint16_t csum_fold(uint32_t csum)
{
	uint32_t sum = csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

static inline uint16_t csum_tcpudp_magic(uint32_t saddr, uint32_t daddr,
					unsigned short len,
					unsigned short proto, uint32_t sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

#if 0
static inline int tcpudp_csum(uint32_t saddr, uint32_t daddr,
				uint16_t len, uint16_t proto,
				const uint8_t *ptr)
{
	uint16_t sum;
	sum = csum_tcpudp_magic(saddr, daddr, len, proto, do_csum_sw(ptr, len));
	return (sum == 0);
}
#else
static inline int tcpudp_csum(uint32_t saddr, uint32_t daddr,
				uint16_t len, uint16_t proto,
				const uint8_t *ptr)
{
	struct tcp_phdr ph;
	uint16_t *tmp;
	uint32_t sum = 0;
	uint16_t csum;
	int i;

	/* Make pseudo-header */
	ph.sip = saddr;
	ph.dip = daddr;
	ph.zero = 0;
	ph.proto = proto;
	ph.tcp_len = htobe16(len);

	/* Checksum the pseudo-header */
	tmp = (uint16_t *)&ph;
	for(i = 0; i < 6; i++)
		sum += tmp[i];

	/* Checksum the header+data */
	tmp = (uint16_t *)ptr;
	for(i = 0; i < (len >> 1); i++)
		sum += tmp[i];

	/* Deal with last byte (if odd number of bytes) */
	if ( len & 1 ) {
		union {
			uint8_t b[2];
			uint16_t s;
		}f;

		f.b[0] = ((uint8_t *)ptr)[len - 1];
		f.b[1] = 0;
		sum += f.s;
	}

	sum = (sum & 0xffff) + (sum >> 16);

	csum = ~sum & 0xffff;

	return (csum == 0);
}
#endif				

#endif /* _CSUM_SW_H */
