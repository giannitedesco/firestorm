#ifndef _PKT_TCP_HEADER_INCLUDED_
#define _PKT_TCP_HEADER_INCLUDED_

/* MISC */
#define TCP_MSS			512
#define TCP_MAXWIN		65535
#define TCP_MAX_WINSHIFT	16

/* TIMEOUTS */
#define TCP_TMO_MSL  (30ULL * TIMESTAMP_HZ)
#define TCP_TMO_2MSL  (2ULL * TCP_TMO_MSL)

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

struct pkt_tcphdr {
	uint16_t	sport,dport;
	uint32_t	seq;
	uint32_t	ack;
#if _BYTE_ORDER == _LITTLE_ENDIAN
	uint8_t		res1:4;	/* ??? */
	uint8_t		doff:4;
#elif _BYTE_ORDER == _BIG_ENDIAN
	uint8_t		doff:4;
	uint8_t		res1:4;	/* ??? */
#endif
	uint8_t 	flags;
	uint16_t	win;
	uint16_t	csum;
	uint16_t	urp;
} _packed;

/* Possible TCP states */
enum {
	TCP_CLOSED = 0,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_ESTABLISHED,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_CLOSING,
	TCP_TIME_WAIT,
	TCP_MAX_STATES /* Leave at the end! */
};

/* TCP pseudo-header for checksumming */
struct tcp_phdr {
	uint32_t sip, dip;
	uint8_t zero, proto;
	uint16_t tcp_len;
};

/* Wrap-safe TCP seq number comparison */
static inline int tcp_before(uint32_t s1, uint32_t s2)
{
	return (int32_t)(s1 - s2) < 0;
}

static inline int tcp_after(uint32_t s1, uint32_t s2)
{
	return (int32_t)(s2 - s1) < 0;
}

#endif /* _PKT_TCP_HEADER_INCLUDED_ */
