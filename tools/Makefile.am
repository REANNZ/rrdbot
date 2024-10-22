
sbin_PROGRAMS = rrdbot-get

rrdbot_get_SOURCES = rrdbot-get.c \
                ../mib/mib-parser.c ../mib/mib-parser.h

rrdbot_get_CFLAGS = -I${top_srcdir}/common/ -I${top_srcdir} \
                -DCONF_PREFIX=\"$(sysconfdir)\" -DDATA_PREFIX=\"$(datadir)\"

rrdbot_get_LDADD = \
	$(top_builddir)/common/libcommon.a \
	$(top_builddir)/bsnmp/libbsnmp-custom.a
