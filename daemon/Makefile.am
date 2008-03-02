
sbin_PROGRAMS = rrdbotd

rrdbotd_SOURCES = rrdbotd.c rrdbotd.h config.c \
                poll-engine.c rrd-update.c \
                ../mib/mib-parser.h ../mib/mib-parser.c

rrdbotd_CFLAGS = \
	-I${top_srcdir}/common/ \
	-I${top_srcdir}/bsnmp/ \
	-I${top_srcdir} \
	-DCONF_PREFIX=\"$(sysconfdir)\" \
	-DDATA_PREFIX=\"$(datadir)\"

rrdbotd_LDADD = \
	$(top_builddir)/common/libcommon.a \
	$(top_builddir)/bsnmp/libbsnmp-custom.a
