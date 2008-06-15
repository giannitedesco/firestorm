/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco
 * This program is released under the terms of the GNU GPL version 2
 *
 * Capdev plugin which uses mmap to read libpcap files.
 *
 * TODO:
 *  o Sliding window to support large files.
*/
#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_fdctl.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef lib_pcap_h

#define pcap_file_header tcpd_file_header
struct tcpd_file_header {
	unsigned int		magic;
	unsigned short		version_major;
	unsigned short		version_minor;
	int			thiszone;
	unsigned int		sigfigs;
	unsigned int		snaplen;
	unsigned int		proto;
};

#define pcap_pkthdr tcpd_pkthdr
struct tcpd_pkthdr {
	struct timeval		ts;
	unsigned int		caplen;
	unsigned int		len;
};
#endif /* lib_pcap_h */

static const struct {
	char * const name;
	unsigned int magic;
	size_t size;
	int swap;
}magics[]={
	{"standard",			0xa1b2c3d4, 16, 0},
	{"redhat",			0xa1b2cd34, 24, 0},
	{"byte-swapped standard",	0xd4c3b2a1, 16, 1},
	{"byte-swapped redhat",		0x34cdb2a1, 24, 1},
	{NULL, 0, 0}
};

/* This is our own private data */
struct tcpd_priv {
	struct _source	src;
	struct _pkt	pkt;
	void		*end;
	void		*cur;
	int		swap;
	size_t		phsiz;
	unsigned int	protocol;
	void		*map;
	unsigned int	map_size;
	int		fd;
	size_t		snaplen;
	unsigned int	(*r32)(unsigned int);
};

static uint32_t read32(uint32_t x)
{
	return x;
}

static uint32_t read32_swap(uint32_t x)
{
	return sys_bswap32(x);
}

static int open_file(struct tcpd_priv *p, const char *fn)
{
	struct stat st;
	struct pcap_file_header *fh;
	int i;

	p->fd = open(fn, O_RDONLY);
	if ( p->fd < 0 ) {
		mesg(M_ERR,"tcpdump: %s: open(): %s", fn, os_err());
		goto err;
	}

	if ( fstat(p->fd, &st) ) {
		mesg(M_ERR,"tcpdump: %s: fstat(): %s", fn, os_err());
		goto err_close;
	}

	p->map_size = (size_t)st.st_size;

	if ( p->map_size < sizeof(struct pcap_file_header) ) {
		mesg(M_ERR,"tcpdump: %s: Not a valid libpcap file", fn);
		goto err_close;
	}

	p->map = mmap(NULL, p->map_size, PROT_READ, MAP_SHARED, p->fd, 0);
	if ( p->map == MAP_FAILED) {
		mesg(M_ERR,"tcpdump: %s: mmap(): %s", fn, os_err());
		goto err_close;
	}

	p->end = p->map + p->map_size;

	fd_close(p->fd);
	p->fd = -1;

#if HAVE_MADVISE && defined(MADV_SEQUENTIAL)
	madvise(p->map, p->map_size, MADV_SEQUENTIAL);
#endif

	fh = (struct pcap_file_header *)p->map;

	/* Check what format the file is */
	for(p->phsiz = i = 0; magics[i].name; i++) {
		if ( fh->magic == magics[i].magic ) {
			if ( magics[i].swap ) {
				p->r32 = read32_swap;
				p->src.s_swab = 1;
			}else{
				p->r32 = read32;
			}

			p->phsiz = magics[i].size;
			p->snaplen = p->r32(fh->snaplen);
			mesg(M_INFO,"tcpdump: %s: %s: snaplen=%u",
				fn, magics[i].name, p->snaplen);
			break;
		}
	}

	if ( !p->phsiz ) {
		mesg(M_ERR,"tcpdump: %s: Bad voodoo magic (0x%x)",
			fn, fh->magic);
		goto err_unmap;
	}

	/* Make sure we can decode this link type, not much point
	 * carrying on if we can't decode anything ;)  */
	p->src.s_decoder = decoder_get(NS_DLT, p->r32(fh->proto));
	if ( p->src.s_decoder == NULL ) {
		mesg(M_ERR,"tcpdump: %s: Unknown proto (0x%x)",
			fn, p->r32(fh->proto));
		goto err_unmap;
	}

	p->cur = p->map;
	p->cur += sizeof(struct pcap_file_header);

	return 1;

err_unmap:
	munmap(p->map, p->map_size);
err_close:
	fd_close(p->fd);
err:
	return 0;
}

/* Stop the capture and cleanup our process */
static void tcpd_free(struct _source *s)
{
	struct tcpd_priv *p = (struct tcpd_priv *)s;

	decode_pkt_realloc(&p->pkt, 0);

	if ( p->map )
		munmap(p->map, p->map_size);

	if ( p->fd >= 0 )
		fd_close(p->fd);

	free(s);
}

static struct _pkt *tcpd_dequeue(struct _source *s, struct iothread *io)
{
	struct tcpd_priv *p = (struct tcpd_priv *)s;
	struct pcap_pkthdr *h;
	struct timeval tmp;

	/* Make sure a packet header is present */
	if ( (p->cur + p->phsiz) > p->end )
		return NULL;

	/* Advance the p->cur to be the start of the
	 * actual packet data */
	h = (struct pcap_pkthdr *)p->cur;
	p->cur += p->phsiz;

	/* Check the packet is present */
	if ( (p->cur + p->r32(h->caplen)) > p->end )
		return NULL;

	/* Fill in the struct packet stuff */
	tmp.tv_sec = p->r32(h->ts.tv_sec);
	tmp.tv_usec = p->r32(h->ts.tv_usec);
	p->pkt.pkt_ts = time_from_timeval(&tmp);
	p->pkt.pkt_len = p->r32(h->len);
	p->pkt.pkt_caplen = p->r32(h->caplen);
	p->pkt.pkt_base = p->cur;
	p->pkt.pkt_end = p->cur + p->pkt.pkt_caplen;

	/* advance the file pointer */
	p->cur += p->pkt.pkt_caplen;

	return &p->pkt;
}

static const struct _capdev capdev = {
	.c_name = "tcpdump",
	.c_dtor = tcpd_free,
	.c_dequeue = tcpd_dequeue,
};

/* Initialise a capture process, we open the file and then
 * return our opaque private data structure to firestorm */
source_t capture_tcpdump_open(const char *fn)
{
	struct tcpd_priv *p;

	p = calloc(1, sizeof(*p));
	if ( p == NULL )
		goto err;

	_source_new(&p->src, &capdev, fn);
	p->pkt.pkt_source = &p->src;
	p->fd = -1;

	if ( !decode_pkt_realloc(&p->pkt, DECODE_DEFAULT_MIN_LAYERS) )
		goto err;

	if ( !open_file(p, fn) )
		goto err;

	return &p->src;

err:
	tcpd_free(&p->src);
	return NULL;
}
