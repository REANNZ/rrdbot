#!/usr/bin/perl

# TODO: We need to make this more resilient
# currently expects args without enforcing

$FIL = $NAM = $SEC = @ARGV[0];

$NAM =~ s/^([^.]+)\..+$/$1/;
$SEC =~ s/^.+\.([^.]+)$/$1/;

$command =     "groff";
@args =        split(" ", "-Tascii -mdoc $FIL");

$enable_include_links = 0;

man($NAM, $SEC);

sub man {
    local($name, $section) = @_;
    local($_, $title, $head, *MAN);
    local($html_name, $html_section, $prefix);
    local(@manargs);
    local($query) = $name;

    # $section =~ s/^([0-9ln]).*$/$1/;
    $section =~ tr/A-Z/a-z/;

    $prefix = "Man ";
    if ($alttitle) {
        $prefix = "";
        $title = &encode_title($alttitle);
        $head = &encode_data($alttitle);
    } elsif ($section) {
        $title = &encode_title("${name}($section)");
        $head = &encode_data("${name}($section)");
    } else {
        $title = &encode_title("${name}");
        $head = &encode_data("${name}");
    }

    print &html_header("$title");
    print "<H1>Man Page: ${title}</H1>";
    print "<PRE>\n";

    $html_name = &encode_data($name);
    $html_section = &encode_data($section);

    #print Dumper($sectionpath);
    #print "yy $section yy $manpath\n";
    if ($name =~ /^\s*$/) {
        print "Empty input, no man page given.\n";
        return;
    }

    if (index($name, '*') != -1) {
        print "Invalid character input '*': $name\n";
        return;
    }

    if ($section !~ /^[0-9ln]\w*$/ && $section ne '') {
        print "Sorry, section `$section' is not valid\n";
        return;
    }

    if (!$section) {
        if ($sectionpath->{$manpath}) {
            $section = "-S " . $sectionpath->{$manpath}{'path'};
        } else {
            $section =  '';
        }
    } else {
        if ($sectionpath->{$manpath}{$section}) {
            $section = "-S " . $sectionpath->{$manpath}{$section};
        } else {
            $section = "-S $section";
        }
    }

    # print "X $command{'man'} @manargs -- x $name x\n";
    &proc(*MAN, $command, @args) ||
        &mydie ("$0: open of $command{'man'} command failed: $!\n");
    if (eof(MAN)) {
        # print "X $command{'man'} @manargs -- x $name x\n";
        print "Sorry, no data found for `$html_name" .
                ($html_section ? "($html_section)": '') . "'.\n";
        return;
    }

    local($space) = 1;
    local(@sect);
    local($i, $j);
    while(<MAN>) {
        # remove tailing white space
        if (/^\s+$/) {
            next if $space;
            $space = 1;
        } else {
            $space = 0;
        }

        $_ = &encode_data($_);
        if($enable_include_links &&
           m,(<B>)?\#include(</B>)?\s+(<B>)?\&lt\;(.*\.h)\&gt\;(</B>)?,) {
            $match = $4; ($regexp = $match) =~ s/\./\\\./;
            s,$regexp,\<A HREF=\"$BASE/usr/include/$match\"\>$match\</A\>,;
        }
        /^\s/ &&                         # skip headers
            s,((<[IB]>)?[\w\_\.\-]+\s*(</[IB]>)?\s*\(([1-9ln][a-zA-Z]*)\)),&mlnk($1),oige;

        # detect E-Mail Addreses in manpages
        if (/\@/) {
            s/([a-z0-9_\-\.]+\@[a-z0-9\-\.]+\.[a-z]+)/<A HREF="mailto:$1">$1<\/A>/gi;
        }

        # detect URLs in manpages
        if (m%tp://%) {
            s,((ftp|http)://[^\s<>\)]+),<A HREF="$1">$1</A>,gi;
        }

        if (/^<B>\S+/ && m%^<B>([^<]+)%) {
            $i = $1; $j = &encode_url($i);
            s%^<B>([^<]+)</B>%<B>$i</B>%;
            push(@sect, $1);
        }
        print;
    }
    close(MAN);

    print "<H6>Copyright, N. Nielsen&nbsp;&nbsp;&nbsp;[ <a href='./'>back</a> | <a href='../../'>home</a> ]</h6>";
    print "</BODY>\n";
    print "</HTML>\n";

    # Sleep 0.35 seconds to avoid DoS attacs
    select undef, undef, undef, 0.35;
}

# encode unknown data for use in <TITLE>...</TITILE>
sub encode_title {
    # like encode_url but less strict (I couldn't find docs on this)
    local($_) = @_;
    s/([\000-\031\%\&\<\>\177-\377])/sprintf('%%%02x',ord($1))/eg;
    $_;
}

# encode unknown data for use in a URL <A HREF="...">
sub encode_url {
    local($_) = @_;
    # rfc1738 says that ";"|"/"|"?"|":"|"@"|"&"|"=" may be reserved.
    # And % is the escape character so we escape it along with
    # single-quote('), double-quote("), grave accent(`), less than(<),
    # greater than(>), and non-US-ASCII characters (binary data),
    # and white space.  Whew.
    s/([\000-\032\;\/\?\:\@\&\=\%\'\"\`\<\>\177-\377 ])/sprintf('%%%02x',ord($1))/eg;
    s/%20/+/g;
    $_;
}
# encode unknown data for use inside markup attributes <MARKUP ATTR="...">
sub encode_attribute {
    # rfc1738 says to use entity references here
    local($_) = @_;
    s/([\000-\031\"\'\`\%\&\<\>\177-\377])/sprintf('\&#%03d;',ord($1))/eg;
    $_;
}
# encode unknown text data for using as HTML,
# treats ^H as overstrike ala nroff.
sub encode_data {
    local($_) = @_;
    local($str);

    # Escape &, < and >
    s,\010[><&],,g;
    s/\&/\&amp\;/g;
    s/\</\&lt\;/g;
    s/\>/\&gt\;/g;

    s,((_\010.)+),($str = $1) =~ s/.\010//g; "<I>$str</I>";,ge;
    s,(.\010)+,$1,g;

    if (!s,((.\010.)+\s+(.\010.)+),($str = $1) =~ s/.\010//g; "<B>$str</B>";,ge) {
        s,((.\010.)+),($str = $1) =~ s/.\010//g; "<B>$str</B>";,ge;
    }

    s,.\010,,g;

    $_;
}

sub html_header {
    return qq{<HTML>
<HEAD>
<TITLE>$_[0]</TITLE>
<link rev="made" href="mailto:wosch\@FreeBSD.ORG">
<META name="robots" content="nofollow">
<meta content="text/html; charset=iso-8859-1" http-equiv="Content-Type">
<link rel="stylesheet" type="text/css" href="/nielsen/style.css">
</HEAD>
<BODY BGCOLOR="#FFFFFF" TEXT="#000000">\n\n};
}

sub mlnk {
    local($matched) = @_;
    return qq{<U>$matched</U>};
}

sub proc {
    local(*FH, $prog, @args) = @_;
    local($pid) = open(FH, "-|");
    return undef unless defined($pid);
    if ($pid == 0) {
    exec $prog, @args;
    &mydie("exec $prog failed\n");
    }
    1;
}

# CGI script must die with error status 0
sub mydie {
	local($message) = @_;
	print &html_header("Error");
	print $message;

print qq{
<p>
<A HREF="$BASE">Index Page and Help</A>
</BODY>
</HTML>
};

	exit(0);
}
