#ifndef __PKT_TCP_HEADER_INCLUDED__
#define __PKT_TCP_HEADER_INCLUDED__

#define FLAG_TCP_CSUM	0x001 /* Checksum OK */
#define FLAG_TCP_STATE	0x002 /* Valid stream */
#define FLAG_TCP_SURE	0x004 /* Assured (seen packets in both directions) */
#define FLAG_TCP_TRACK	0x008 /* Conntrack is even on? */
#define FLAG_TCP_2SVR	0x010 /* To server */
#define FLAG_TCP_CT_EST	0x020 /* 3-way handshake complete */
#define FLAG_TCP_SACK	0x040 /* This packet is a selective ACK */
#define FLAG_TCP_STREAM	0x080 /* Reassembling */
#define FLAG_TCP_TAGSV	0x100 /* Tag server stream */
#define FLAG_TCP_TAGCL	0x200 /* Tag client stream */

/* MISC */
#define TCP_MSS			512
#define TCP_MAXWIN		65535
#define TCP_MAX_WINSHIFT	16

/* OPTIONS */
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MAXSEG 2
#define TCPOPT_WSCALE 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOPT_SACK 5
#define TCPOPT_ECHO 6
#define TCPOPT_ECHOREPLY 7
#define TCPOPT_TIMESTAMP 8
#define TCPOPT_POC_PERMITTED 9
#define TCPOPT_POC 10
#define TCPOPT_CC 11
#define TCPOPT_CCNEW 12
#define TCPOPT_CCECHO 13
#define TCPOPT_MAX 14

#define TCPOLEN_EOL 1
#define TCPOLEN_NOP 1
#define TCPOLEN_MAXSEG 4
#define TCPOLEN_WSCALE 3
#define TCPOLEN_SACK_PERMITTED 2
#define TCPOLEN_ECHO 6
#define TCPOLEN_ECHOREPLY 6
#define TCPOLEN_TIMESTAMP 10
#define TCPOLEN_CC 6
#define TCPOLEN_CCNEW 6
#define TCPOLEN_CCECHO 6
#define TCPOLEN_POC_PERMITTED 2
#define TCPOLEN_POC 3

/* TCP FLAGS */
#define TCP_FIN		0x01	/* Finish */
#define TCP_SYN		0x02	/* Synchronise */
#define TCP_RST		0x04	/* Reset */
#define TCP_PSH		0x08	/* Push */
#define TCP_ACK		0x10	/* Acknowlege */
#define TCP_URG		0x20	/* Urgent pointer */
#define TCP_ECE		0x40	/* ECN echo */
#define TCP_CWR		0x80	/* Congestion window reduced */

#define TCP_STD		(TCP_FIN|TCP_SYN|TCP_RST|TCP_PSH|TCP_ACK|TCP_URG)

typedef union _tcpflags {
	uint8_t flags;
	struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t fin:1;
	uint8_t syn:1;
	uint8_t rst:1;
	uint8_t psh:1;
	uint8_t ack:1;
	uint8_t urg:1;
	uint8_t ece:1;
	uint8_t cwr:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t cwr:1;
	uint8_t ece:1;
	uint8_t urg:1;
	uint8_t ack:1;
	uint8_t psh:1;
	uint8_t rst:1;
	uint8_t syn:1;
	uint8_t fin:1;
#else
#error "Couldn't determine endianness"
#endif
	}bits;
}tcpflags;

struct pkt_tcphdr
{
	uint16_t	sport,dport;
	uint32_t	seq;
	uint32_t	ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t	res1:4;	/* ??? */
	uint8_t	doff:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t	doff:4;
	uint8_t	res1:4;	/* ??? */
#endif
	tcpflags	flags;
	uint16_t	win;
	uint16_t	csum;
	uint16_t	urp;
};

/* Possible TCP states */
enum{
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING,	 /* now a valid state */
	TCP_MAX_STATES /* Leave at the end! */
};

/* TCP pseudo-header for checksumming */
struct tcp_phdr {
	uint32_t sip, dip;
	uint8_t zero, proto;
	uint16_t tcp_len;
};

#define TF_SACK_OK	(1<<0)
#define TF_WSCALE_OK	(1<<1)
#define TF_TSTAMP_OK	(1<<2)

/* A simplex tcp stream */
/* XXX: Do not modify this structure - it is an on-disk
 * elog structure and will break binary compatibility.
 */
struct tcp_stream {
	uint8_t	state; /* from above enum */
	uint8_t	flags; /* optional features */
	uint8_t	scale; /* scaling factor */
	uint8_t	queue; /* in queue mode */

	uint32_t	ts_recent; /* a recent timestamp */
	uint32_t	ts_recent_stamp; /* local time on it */

	uint32_t	snd_una; /* first byte we want ack for */
	uint32_t	snd_nxt; /* next sequence to send */

	uint32_t	rcv_nxt; /* what we want to recv next */
	uint32_t	rcv_wnd; /* receiver window */
	uint32_t	rcv_wup; /* rcv_nxt on last window update */

	uint32_t	isn; /* equivalent of rfc793 iss */
};

/* Reassembly buffer */
struct tcp_sbuf {
	struct tcpr_node *root; /* root node of rbtree */
	uint32_t begin; /* sequence number of first
			 * byte (not always rcv_nxt) */
	uint32_t reasm_begin; /* sequence number of first unswallowed byte */
};

struct tcp_tag {
	uint16_t metric;
	uint16_t count;
	struct alert *alert;
};

/* A duplex tcp session */
struct tcp_session {
	/* Global LRU list */
	struct list_head lru;

	/* Timeout list, for SYN timeouts etc.. */
	struct list_head tmo;

	/* Hash table collision chaining */
	struct tcp_session **hash_pprev, *hash_next;

	/* TCP state: network byte order */
	uint32_t c_addr, s_addr;
	uint16_t c_port, s_port;

	struct tcp_tag c_tag, s_tag;

	/* TCP state: host byte order */
	struct tcp_stream client;
	struct tcp_stream server;

	struct tcp_sbuf c_reasm;
	struct tcp_sbuf s_reasm;

	/* Application layer protocol carried on this stream */
	struct proto *proto;

	/* Application layer state (flow information) */
	void *flow;

	/* expiry time */
	timestamp_t expire;
};

/* tcp_session allocator union */
union tcp_union {
	union tcp_union *next;
	struct tcp_session s;
};

/* serialised TCP stream data */
struct tcp_serial {
	uint32_t c_addr, s_addr;
	uint16_t c_port, s_port;
	struct tcp_stream client;
	struct tcp_stream server;
};

/* Wrap-safe TCP seq number comparison */
static __inline__ int tcp_before(uint32_t s1, uint32_t s2) {
	return (int32_t)(s1-s2) < 0;
}

static __inline__ int tcp_after(uint32_t s1, uint32_t s2) {
	return (int32_t)(s2-s1) < 0;
}
#endif /* __PKT_TCP_HEADER_INCLUDED__ */
