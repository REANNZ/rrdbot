#!/bin/sh -e

set -e

aclocal
autoheader
automake -a
autoconf
./configure --enable-maintainer-mode "$@"

