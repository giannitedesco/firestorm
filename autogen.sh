#!/bin/sh
libtoolize --automake -c -f && \
aclocal && \
autoheader && \
automake --gnu -a -c -f && \
autoconf && \
test -x ./configure && ./configure $@
