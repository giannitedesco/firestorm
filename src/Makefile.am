## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I../include

bin_PROGRAMS = firestorm

if HAVE_EPOLL
SRC_EPOLL = nbio-epoll.c
endif

if HAVE_PCAP
firestorm_LDADD = @pcap_ldflags@
SRC_PCAP = c_pcap.c
endif

firestorm_SOURCES = \
	c_tcpdump.c \
	$(SRC_PCAP) \
	\
	ft_ipdefrag.c \
	ft_tcpflow.c \
	p_ether.c \
	p_ipx.c \
	p_ipv4.c \
	p_ipv6.c \
	p_null.c \
	p_sll.c \
	p_arp.c \
	\
	memchunk.c \
	timers.c \
	mpool.c \
	fdctl.c \
	nbio.c \
	$(SRC_EPOLL) \
	nbio-poll.c \
	mesg.c \
	util.c \
	os.c \
	\
	capture.c \
	packet.c \
	decode.c \
	\
	s_pipeline.c \
	sensor.c \
	s_mesg.c
