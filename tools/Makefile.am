
sbin_PROGRAMS = rrdbot-create

rrdbot_create_SOURCES = rrdbot-create.c ../common/usuals.h \
                ../common/config-parser.h ../common/config-parser.c \
                ../common/compat.h ../common/compat.c
rrdbot_create_CFLAGS = -I${top_srcdir}/common/ -I${top_srcdir} \
                -DCONF_PREFIX=\"$(sysconfdir)\" -DDATA_PREFIX=\"$(datadir)\"
