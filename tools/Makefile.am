
sbin_PROGRAMS = rrdbot-create rrdbot-get

rrdbot_create_SOURCES = rrdbot-create.c ../common/usuals.h \
                ../common/config-parser.h ../common/config-parser.c \
                ../common/compat.h ../common/compat.c
rrdbot_create_CFLAGS = -I${top_srcdir}/common/ -I${top_srcdir} \
                -DCONF_PREFIX=\"$(sysconfdir)\" -DDATA_PREFIX=\"$(datadir)\"

rrdbot_get_SOURCES = rrdbot-get.c ../common/usuals.h \
                ../common/compat.h ../common/compat.c \
                ../common/config-parser.h ../common/config-parser.c \
                ../common/server-mainloop.h ../common/server-mainloop.c \
                ../common/sock-any.h ../common/sock-any.c \
                ../mib/mib-parser.c ../mib/mib-parser.h \
                ../bsnmp/asn1.h ../bsnmp/asn1.c \
                ../bsnmp/snmp.h ../bsnmp/snmp.c
rrdbot_get_CFLAGS = -I${top_srcdir}/common/ -I${top_srcdir} \
                -DCONF_PREFIX=\"$(sysconfdir)\" -DDATA_PREFIX=\"$(datadir)\"
