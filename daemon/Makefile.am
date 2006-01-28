
sbin_PROGRAMS = rrdbotd

rrdbotd_SOURCES = rrdbotd.c rrdbotd.h config.c usuals.h \
                snmp-help.c snmp-engine.c rrd-update.c \
                ../common/server-mainloop.c ../common/server-mainloop.h \
                ../common/sock-any.h ../common/sock-any.c \
                ../common/compat.h ../common/compat.c \
                ../common/hash.h ../common/hash.c \
                ../common/config-parser.h ../common/config-parser.c \
                ../mib/parse.c
rrdbotd_CFLAGS = -I${top_srcdir}/common/ -I${top_srcdir}/bsnmp/ -I${top_srcdir} \
                 -DCONF_PREFIX=\"$(sysconfdir)\" -DDATA_PREFIX=\"$(datadir)\"
rrdbotd_LDADD = $(top_builddir)/bsnmp/libbsnmp-custom.a
