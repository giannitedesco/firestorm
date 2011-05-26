dnl Process this file with autoconf to produce a configure script.

AC_INIT(firestorm,0.6.0,[gianni@scaramanga.co.uk],firestorm)
AM_INIT_AUTOMAKE()
AM_CONFIG_HEADER(include/config.h)

dnl Check for programs
AC_ISC_POSIX
AC_PROG_AWK
AC_PROG_CC
AM_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

dnl libtool stuff
dnl AM_DISABLE_STATIC
dnl AC_LIBTOOL_DLOPEN
dnl AC_LIBTOOL_WIN32_DLL
dnl AC_DISABLE_SHARED
dnl AC_PROG_LIBTOOL
dnl AM_PROG_LIBTOOL
dnl AC_SUBST(LIBTOOL_DEPS)

dnl Set our cflags if we are using gcc
if test "$GCC" = yes; then
	CFLAGS="${CFLAGS} -Os -pipe -Wall -Wsign-compare -Wcast-align -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn -finline-functions"
	#-Wmissing-format-attribute"
fi

dnl Check for headers
AC_HEADER_TIME
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_SYS_LARGEFILE
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h netinet/in.h sys/uio.h])
AC_CHECK_HEADERS([stdlib.h string.h sys/socket.h sys/time.h unistd.h assert.h])
AC_CHECK_HEADERS([sys/resource.h getopt.h pwd.h sys/poll.h sys/epoll.h])
AC_CHECK_HEADERS([sys/endian.h endian.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_C_INLINE
AC_STRUCT_TM

dnl Check for library functions
AC_CHECK_FUNCS([tzset sigaction getrusage getopt_long madvise getpwnam])
AC_CHECK_FUNCS([poll writev sigprocmask])

dnl Check for memory mapped IO support
havemm="no"
AC_FUNC_MMAP(havemm="$withval")
if test "x$havemm" != "xno"; then
	echo "ERROR: firestorm needs mmap()/munmap() to compile."
	echo "ERROR: get a real OS."
	exit 1
fi

AC_CHECK_FUNC(epoll_create,[have_epoll=1], [have_epoll=0])
AM_CONDITIONAL([HAVE_EPOLL], [test x$have_epoll == x1])
AC_DEFINE_UNQUOTED([HAVE_EPOLL], $have_epoll, [If nbio epoll module is built])

dnl Check for libpcap -- shamelessly stolen from snort
AC_ARG_WITH(libpcap_includes,
	[  --with-libpcap-includes=DIR  libcap include directory],
	[with_libpcap_includes="$withval"],[with_libpcap_includes=no])

AC_ARG_WITH(libpcap_libraries,
	[  --with-libpcap-libraries=DIR  libcap library directory],
	[with_libpcap_libraries="$withval"],[with_libpcap_libraries=no])

if test "x$with_libpcap_includes" != "xno"; then
	CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
fi

if test "x$with_libpcap_libraries" != "xno"; then
	LDFLAGS="${LDFLAGS}  -L${with_libpcap_libraries}"
fi

AC_CHECK_LIB(pcap, pcap_datalink, [have_pcap=1], [have_pcap=0])
AM_CONDITIONAL([HAVE_PCAP], [test x$have_pcap == x1])
AC_DEFINE_UNQUOTED([HAVE_PCAP], $have_pcap, [If nbio libpcap capture is built])
if test "x$have_pcap" != "xno"; then
	pcap_ldflags="-lpcap"
else
	pcap_ldflags=""
fi
AC_SUBST(pcap_ldflags)

dnl Check for Linux mmap() packet socket 
linux_la="no"
AC_MSG_CHECKING(for Linux mmap packet socket)
AC_TRY_COMPILE([
#include <linux/if_packet.h>
#include <asm/system.h>
int main(int argc, char **argv)
{
	mb();
	return 0;
}
],
[
static int x = PACKET_RX_RING;
mb();
],[linux_la="yes"],[linux_la="no"])
AC_MSG_RESULT($linux_la)
if test "x$linux_la" == "xno"; then
	linux_la=""
else
	linux_la="capdev_linux.la"
fi
AC_SUBST(linux_la)

dnl Make our Makefiles
AC_OUTPUT([
Makefile
src/Makefile
])
