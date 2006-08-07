
man_MANS = rrdbotd.8 rrdbot.conf.5 rrdbot-create.8 rrdbot-get.1

# Simple way to make docs
html:
	perl man2html.pl rrdbotd.8 > rrdbotd.8.html
	perl man2html.pl rrdbot.conf.5 > rrdbot.conf.5.html
	perl man2html.pl rrdbot-create.8 > rrdbot-create.8.html
	perl man2html.pl rrdbot-get.1 > rrdbot-get.1.html

EXTRA_DIST = $(man_MANS) \
    man2html.pl
