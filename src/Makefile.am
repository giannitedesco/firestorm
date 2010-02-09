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
	memchunk.c \
	timers.c \
	fdctl.c \
	nbio.c \
	$(SRC_EPOLL) \
	nbio-poll.c \
	mesg.c \
	util.c \
	vec.c \
	os.c \
	\
	capture.c \
	decode.c \
	\
	c_tcpdump.c \
	$(SRC_PCAP) \
	\
	p_null.c \
	p_sll.c \
	p_ether.c \
	p_arp.c \
	\
	p_ipx.c \
	p_ipv6.c \
	\
	p_ipv4.c \
	ft_ipdefrag.c \
	ft_tcpflow.c \
	tcp_reasm.c \
	tcp_app.c \
	\
	sp_http.c \
	\
	s_pipeline.c \
	s_mesg.c \
	sensor.c

#	sp_smtp.c \
#	sp_pop3.c \
#	sp_ftp.c \
#	\
#	sp_smb.c \
#
