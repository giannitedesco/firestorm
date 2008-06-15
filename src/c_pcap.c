/*
 * This file is part of Firestorm NIDS
 * Copyright (c) 2002,2003,2004 Gianni Tedesco <gianni@scaramanga.co.uk>
 * This program is released under the terms of the GNU GPL version 2
*/
#include <firestorm.h>
#include <f_capture.h>
#include <f_packet.h>
#include <f_decode.h>
#include <f_fdctl.h>

#include <pcap.h>

#define READ_TIMEOUT 500

struct fpcap_priv {
	struct _source	src;
	struct _pkt	pkt;
	pcap_t		*pcap_desc;
};

static int setup_decode(struct fpcap_priv *p)
{
	unsigned int lnk;
	
	lnk = pcap_datalink(p->pcap_desc);

	p->src.s_decoder = decoder_get(NS_DLT, lnk);
	if ( p->src.s_decoder == NULL ) {
		mesg(M_ERR,"pcap: %s: Can't support protocol 0x%x",
			p->src.s_name, lnk);
		return 0;
	}

	if ( !decode_pkt_realloc(&p->pkt, DECODE_DEFAULT_MIN_LAYERS) )
		return 0;

	return 1;
}

static void pcap_free(struct _source *s)
{
	struct fpcap_priv *p = (struct fpcap_priv *)s;
	struct pcap_stat stat;

	if ( p == NULL )
		return;

        if (!pcap_file(p->pcap_desc) && pcap_stats(p->pcap_desc, &stat) < 0) {
		mesg(M_ERR, "pcap: pcap_stats(): %s",
			pcap_geterr(p->pcap_desc));
        }else{
		mesg(M_INFO,"pcap: received %u packets, dropped %u",
			stat.ps_recv, stat.ps_drop);
	}

	decode_pkt_realloc(&p->pkt, 0);

	if ( p->pcap_desc )
		pcap_close(p->pcap_desc);

	free(p);
}

static void lpf_callback(u_char *user, struct pcap_pkthdr *header, u_char *data)
{
	struct fpcap_priv *p;

	p = (struct fpcap_priv *)user;
	if ( p == NULL )
		return;

	p->pkt.pkt_ts = time_from_timeval(&header->ts);
	p->pkt.pkt_len = header->len;
	p->pkt.pkt_caplen = header->caplen;
	p->pkt.pkt_base = data;
	p->pkt.pkt_end = data + header->caplen;
}

static struct _pkt *live_dequeue(struct _source *s, struct iothread *io)
{
	struct fpcap_priv *p = (struct fpcap_priv *)s;
	int ret;
	
	ret = pcap_dispatch(p->pcap_desc, -1,
		(pcap_handler)lpf_callback, (u_char *)p);

	if ( ret < 0 ) {
		mesg(M_ERR, "pcap: %s", pcap_geterr(p->pcap_desc));
		nbio_del(io, &s->s_io);
		source_free(s);
		return NULL;
	}

	if ( ret == 0 ) {
		nbio_inactive(io, &s->s_io);
		return NULL;
	}

	return &p->pkt;
}

static struct _pkt *file_dequeue(struct _source *s, struct iothread *io)
{
	struct fpcap_priv *p = (struct fpcap_priv *)s;
	int ret;
	
	ret = pcap_dispatch(p->pcap_desc, 1,
		(pcap_handler)lpf_callback, (u_char *)p);

	if ( ret < 0 ) {
		mesg(M_ERR, "pcap: %s", pcap_geterr(p->pcap_desc));
		return NULL;
	}

	if ( ret == 0 )
		return NULL;

	return &p->pkt;
}

static const struct _capdev c_live = {
	.c_flags = CAPDEV_ASYNC,
	.c_name = "pcap.live",
	.c_dtor = pcap_free,
	.c_dequeue = live_dequeue,
};
static const struct _capdev c_offline = {
	.c_name = "pcap.offline",
	.c_dtor = pcap_free,
	.c_dequeue = file_dequeue,
};

source_t capture_pcap_open_offline(const char *fn)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	struct fpcap_priv *p;

	p = calloc(1, sizeof(*p));
	if ( p == NULL )
		return 0;

	_source_new(&p->src, &c_offline, fn);
	p->pkt.pkt_source = &p->src;

	ebuf[0] = '\0';
	p->pcap_desc = pcap_open_offline(fn, ebuf);
	if ( p->pcap_desc == NULL ) {
		mesg(M_ERR,"pcap: %s", ebuf);
		goto err;
	}

	if ( !setup_decode(p) )
		goto err;

	return &p->src;
err:
	free(p);
	return NULL;
}

source_t capture_pcap_open_live(const char *ifname, size_t mtu, int promisc)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	struct fpcap_priv *p;

	assert(ifname != NULL);
	assert(mtu > 0);

	p = calloc(1, sizeof(*p));
	if ( p == NULL )
		return 0;

	_source_new(&p->src, &c_live, ifname);
	p->pkt.pkt_source = &p->src;

	ebuf[0] = '\0';
	p->pcap_desc = pcap_open_live(ifname, mtu, promisc,
					READ_TIMEOUT, ebuf);
	if ( p->pcap_desc == NULL ) {
		mesg(M_ERR,"pcap: %s", ebuf);
		goto err;
	}

	if ( ebuf[0] != '\0' )
		mesg(M_WARN, "pcap: %s", ebuf);

	p->src.s_swab = !!pcap_is_swapped(p->pcap_desc);

	if ( !setup_decode(p) )
		goto err;

	if ( pcap_setnonblock(p->pcap_desc, 1, ebuf) ) {
		mesg(M_ERR, "pcap: %s", ebuf);
		goto err;
	}

	p->src.s_io.fd = pcap_fileno(p->pcap_desc);

	return &p->src;
err:
	free(p);
	return NULL;
}
