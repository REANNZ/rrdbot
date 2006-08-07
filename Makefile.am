
EXTRA_DIST = common mib acsite.m4
SUBDIRS = bsnmp daemon tools mibs doc

# Clean up any EXTRA_DIST we're distributing
dist-hook:
	rm -rf `find $(distdir)/ -name .svn`

# Make the config directory
install-exec-hook:
	mkdir -p $(DESTDIR)$(sysconfdir)/rrdbot
