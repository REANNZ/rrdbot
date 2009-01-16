/*
 * Copyright (c) 2005, Stefan Walter
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 *
 */

#include "usuals.h"
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <err.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>
#include <mib/mib-parser.h>

#include "config-parser.h"
#include "log.h"
#include "server-mainloop.h"
#include "snmp-engine.h"
#include "sock-any.h"

#define DEFAULT_TIMEOUT     5000        /* Default timeout for SNMP response */
#define MAX_RETRIES         3           /* Number of SNMP packets we retry */

struct context
{
	struct asn_oid oid_first;           	/* The first OID we've done */

	/* Request data */
	char host[128];                    	/* The remote host, resolved to an address */
	char *community;			/* The community to use */
	int version;				/* protocol version */

	struct asn_oid request_oid;		/* The OID to request */

	int has_query;				/* Whether we are a table query or not */
	struct asn_oid query_oid;		/* OID to use in table query */
	char *query_match;			/* Value to match in table query */

	uint64_t timeout;                   /* Receive timeout */

	int recursive;                      /* Whether we're going recursive or not */
	int numeric;                        /* Print raw data */
	int verbose;				/* Print verbose messages */
};

static struct context ctx;

/* -----------------------------------------------------------------------------
 * REQUIRED CALLBACK FUNCTIONS
 */

int
cfg_value(const char* filename, const char* header, const char* name,
          char* value, void* data)
{
    return 0;
}

int
cfg_error(const char* filename, const char* errmsg, void* data)
{
    return 0;
}

void
log_vmessage (int level, int erno, const char *msg, va_list va)
{
	if (level >= LOG_DEBUG && !ctx.verbose)
		return;

	if (erno) {
		errno = erno;
		vwarn (msg, va);
	} else {
		vwarnx (msg, va);
	}

	if (level <= LOG_ERR)
		exit (1);
}

/* -----------------------------------------------------------------------------
 * SNMP ENGINE
 */

static void
parse_host (char *host)
{
	struct sockaddr_any addr;
	char *x;

	/* Use the first of multiple hosts */
	x = strchr (host, ',');
	if (x) {
		*x = 0;
		warnx ("only using the first host name: %s", host);
	}

	if (sock_any_pton (host, &addr, SANY_OPT_DEFPORT(161) | SANY_OPT_DEFLOCAL) == -1)
		err (1, "couldn't resolve host address: %s", host);

	if (sock_any_ntop (&addr, ctx.host, sizeof (ctx.host), 0) == -1)
		err (1, "couldn't convert host address: %s", host);
}

static void
parse_argument (char *uri)
{
	enum snmp_version version;
	const char* msg;
	char* copy;
	char *user, *host, *scheme, *path, *query;
	char *value, *name;

	/* Parse the SNMP URI */
	copy = strdup (uri);
	msg = cfg_parse_uri (uri, &scheme, &host, &user, &path, &query);
	if (msg)
		errx (2, "%s: %s", msg, copy);
	free (copy);

	ASSERT (host && path);

	/* Host, community */
	parse_host (host);
	ctx.community = user ? user : "public";

	/* Currently we only support SNMP pollers */
	msg = cfg_parse_scheme (scheme, &version);
	if (msg)
		errx (2, "%s: %s", msg, scheme);
	ctx.version = version;

	/* Parse the OID */
	if (mib_parse (path, &ctx.request_oid) == -1)
		errx (2, "invalid MIB: %s", path);
	if (ctx.request_oid.len >= ASN_MAXOIDLEN)
		errx (2, "request OID is too long");

	/* Parse any query */
	if (query) {
		msg = cfg_parse_query (query, &name, &value, &query);
		if (msg)
			errx (2, "%s", msg);
		if (query && *query)
			warnx ("only using first query argument in snmp URI");

		ctx.has_query = 1;
		ctx.query_match = value;

		/* And parse the query OID */
		if (mib_parse (name, &(ctx.query_oid)) == -1)
			errx (2, "invalid MIB: %s", name);

		if (ctx.query_oid.len >= ASN_MAXOIDLEN)
			errx (2, "query OID is too long");
	}
}

static void
print_result (struct snmp_value* value)
{
	char *t;

	if (ctx.numeric)
		printf ("%s", asn_oid2str (&value->var));
	else
		mib_format (&value->var, stdout, ctx.verbose);

	printf(": ");

        switch (value->syntax) {
	case SNMP_SYNTAX_NULL:
		printf ("[null]\n");
		break;
	case SNMP_SYNTAX_INTEGER:
		printf ("%d\n", value->v.integer);
		break;
	case SNMP_SYNTAX_COUNTER:
	case SNMP_SYNTAX_GAUGE:
	case SNMP_SYNTAX_TIMETICKS:
		printf ("%u\n", value->v.uint32);
		break;
	case SNMP_SYNTAX_COUNTER64:
		printf ("%llu\n", value->v.counter64);
		break;
	case SNMP_SYNTAX_OCTETSTRING:
		t = xcalloc (value->v.octetstring.len + 1);
		memcpy (t, value->v.octetstring.octets, value->v.octetstring.len);
		printf ("%s\n", t);
		free (t);
		break;
	case SNMP_SYNTAX_OID:
		printf ("%s\n", asn_oid2str(&(value->v.oid)));
		break;
	case SNMP_SYNTAX_IPADDRESS:
		printf ("%c.%c.%c.%c\n", value->v.ipaddress[0],
		        value->v.ipaddress[1], value->v.ipaddress[2],
		        value->v.ipaddress[3]);
		break;
	case SNMP_SYNTAX_NOSUCHOBJECT:
		printf ("[field not available on snmp server]\n");
		break;
	case SNMP_SYNTAX_NOSUCHINSTANCE:
		printf ("[no such instance on snmp server]\n");
		break;
	case SNMP_SYNTAX_ENDOFMIBVIEW:
		printf ("[end of mib view on snmp server]\n");
		break;
	default:
		printf ("[unknown]\n");
		break;
	}
}

static void
had_failure (int code)
{
	ASSERT (code != 0);

	if (code < 1)
		errx (1, "couldn't successfully communicate with server at: %s", ctx.host);
	else
		errx (1, "server returned error: %s", snmp_get_errmsg (code));
}

static void
process_recursive (void)
{
	struct snmp_value value;
	struct asn_oid last;
	int i, ret, done;

	memcpy (&last, &ctx.request_oid, sizeof (last));
	memset (&value, 0, sizeof (value));

	for (i = 0; ; ++i) {

		memcpy (&value.var, &last, sizeof (value.var));

		ret = snmp_engine_sync (ctx.host, ctx.community, ctx.version,
		                        0, ctx.timeout, SNMP_PDU_GETNEXT, &value);

		/* Reached the end */
		if (i == 0 && ret == SNMP_ERR_NOSUCHNAME)
			return;

		if (ret != SNMP_ERR_NOERROR) {
			had_failure (ret);
			return;
		}

		/* Check that its not past the end */
		done = asn_compare_oid (&ctx.request_oid, &value.var) != 0 &&
		        !asn_is_suboid (&ctx.request_oid, &value.var);

		if (!done) {
			print_result (&value);
			memcpy (&last, &value.var, sizeof (last));
		}

		snmp_value_clear (&value);

		if (done)
			return;
	}
}

static void
process_query (void)
{
	struct snmp_value value;
	struct snmp_value match;
	asn_subid_t sub;
	int matched, ret;

	ASSERT (ctx.has_query);
	memset (&value, 0, sizeof (value));
	memset (&match, 0, sizeof (match));

	/* Build up the query OID we're going for */
	memcpy (&value.var, &ctx.query_oid, sizeof (value.var));
	ASSERT (value.var.len < ASN_MAXOIDLEN);

	/* Loop looking for the value */
	for (;;) {

		/* Do the request */
		ret = snmp_engine_sync (ctx.host, ctx.community, ctx.version,
		                        0, ctx.timeout, SNMP_PDU_GETNEXT, &value);

		/* Convert these result codes into 'not found' */
		if (ret == SNMP_ERR_NOERROR) {
			switch (value.syntax) {
			case SNMP_SYNTAX_NOSUCHOBJECT:
			case SNMP_SYNTAX_NOSUCHINSTANCE:
			case SNMP_SYNTAX_ENDOFMIBVIEW:
				ret = SNMP_ERR_NOSUCHNAME;
				break;
			default:
				break;
			}
		}

		if (ret != SNMP_ERR_NOERROR) {
			had_failure (ret);
			return;
		}

		/* Match the results */
		if (ctx.query_match)
			matched = snmp_engine_match (&value, ctx.query_match);

		/* When query match is null, anything matches */
		else
			matched = 1;

		if (matched)
			break;
	}

	/* The last one is the table index */
	sub = value.var.subs[value.var.len - 1];

	/* Build up the field OID */
	memcpy (&value.var, &ctx.request_oid, sizeof (value.var));
	ASSERT (value.var.len < ASN_MAXOIDLEN);
	value.var.subs[value.var.len] = sub;
	value.var.len++;

	ret = snmp_engine_sync (ctx.host, ctx.community, ctx.version,
	                        0, ctx.timeout, SNMP_PDU_GET, &value);

	if (ret != SNMP_ERR_NOERROR)
		had_failure (ret);
	else
		print_result (&value);
}

static void
process_simple (void)
{
	struct snmp_value value;
	int ret;

	memset (&value, 0, sizeof (value));
	memcpy (&value.var, &ctx.request_oid, sizeof (value.var));

	ret = snmp_engine_sync (ctx.host, ctx.community, ctx.version,
	                        0, ctx.timeout, SNMP_PDU_GET, &value);

	if (ret != SNMP_ERR_NOERROR)
		had_failure (ret);
	else
		print_result (&value);

	snmp_value_clear (&value);
}

/* -----------------------------------------------------------------------------
 * STARTUP
 */

static void
usage()
{
    fprintf(stderr, "usage: rrdbot-get -V\n");
    fprintf(stderr, "       rrdbot-get [-Mnrv] [-t timeout] [-m mibdir] [-s srcaddr] snmp://community@host/oid\n");
    exit(2);
}

static void
version()
{
    printf("rrdbot-get (version %s)\n", VERSION);
    exit(0);
}

int
main (int argc, char* argv[])
{
	char *bind_address = NULL;
	char ch;
	char* t;

	/* Defaults */
	memset (&ctx, 0, sizeof (ctx));
	ctx.timeout = DEFAULT_TIMEOUT;

	/* Parse the arguments nicely */
	while ((ch = getopt (argc, argv, "m:Mnrs:t:vV")) != -1) {
		switch (ch)
		{

		/* mib directory */
		case 'm':
			mib_directory = optarg;
			break;

		/* MIB load warnings */
		case 'M':
			mib_warnings = 1;
			break;

		/* Numeric output */
		case 'n':
			ctx.numeric = 1;
			break;

		/* SNMP walk (recursive)*/
		case 'r':
			ctx.recursive = 1;
			break;

		/* local source address */
		case 's':
			bind_address = optarg;
			break;

		/* The timeout */
		case 't':
			ctx.timeout = strtoul (optarg, &t, 10);
			if (*t)
				errx (2, "invalid timeout: %s", optarg);
			ctx.timeout *= 1000;
			break;

		/* Verbose */
		case 'v':
			ctx.verbose = 1;
			break;

		/* Print version number */
		case 'V':
			version ();
			break;

		/* Usage information */
		case '?':
		default:
			usage ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if(argc != 1)
		usage ();

	server_init ();
    	snmp_engine_init (bind_address, MAX_RETRIES);

    	parse_argument (argv[0]);

    	/*
    	 * Recursive query walks everything at or lower than the
    	 * specified OID in the tree.
    	 */
    	if (ctx.recursive) {
    		if (ctx.has_query)
    			errx (2, "cannot do a recursive table query");
    		process_recursive ();

    	/*
    	 * Does a table query, lookup the appropriate row, and
    	 * the value of the OID for that row.
    	 */
    	} else if (ctx.has_query) {
    		ASSERT (!ctx.recursive);
    		process_query ();

    	/*
    	 * A simple value lookup.
    	 */
    	} else {
    		process_simple ();
    	}

    	snmp_engine_stop ();
    	server_uninit ();

    	return 0;
}
