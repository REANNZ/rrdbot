SUBDIRS = bsnmp

sbin_PROGRAMS = rrdbotd

rrdbotd_SOURCES = rrdbotd.c rrdbotd.h config.c \
                snmp-help.c snmp-engine.c rrd-update.c \
                common/server-mainloop.c common/server-mainloop.h \
                common/sock-any.h common/sock-any.c \
                usuals.h common/stringx.h common/stringx.c common/hash.h common/hash.c
rrdbotd_CFLAGS = -I${top_srcdir}/src/common/ -I${top_srcdir} -Ibsnmp
rrdbotd_LDADD = $(top_builddir)/src/bsnmp/libbsnmp-custom.a
