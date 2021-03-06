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

#include "async-resolver.h"
#include "log.h"
#include "rrdbotd.h"
#include "server-mainloop.h"
#include "snmp-engine.h"

#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <signal.h>
#include <err.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>
#include <mib/mib-parser.h>


/* The default command line options */
#define DEFAULT_CONFIG      CONF_PREFIX "/rrdbot"
#define DEFAULT_WORK        "/var/db/rrdbot"
#define DEFAULT_RETRIES     3
#define DEFAULT_TIMEOUT     5

/* -----------------------------------------------------------------------------
 * GLOBALS
 */

/* The one main state object */
rb_state g_state;

/* Some logging flags */
static int daemonized = 0;
static int debug_level = LOG_ERR;

#include "mib/parse.h"

#ifdef TEST

static void
test(int argc, char* argv[])
{
    struct snmp_value val;

    debug_level = 4;

    if(argc < 2)
        errx(2, "specify arguments");

    while(argc > 1)
    {
        if(rb_snmp_parse_mib(argv[1], &val) == -1)
            warnx("couldn't parse mib value: %s", argv[1]);
        else
            fprintf(stderr, "the oid is: %s\n", asn_oid2str(&(val.var)));

        argc--;
        argv++;
    }

    rb_mib_uninit();
    exit(1);
}

#endif /* TEST */

/* -----------------------------------------------------------------------------
 * LOGGING
 */

void
log_vmessage(int level, int erno, const char* msg, va_list ap)
{
    #define MAX_MSGLEN  1024
    char buf[MAX_MSGLEN];

    if(daemonized) {
        if (level >= LOG_DEBUG)
            return;
    } else {
        if(debug_level < level)
            return;
    }

    ASSERT (msg);

    /* Cleanup the message a little */
    strlcpy(buf, msg, MAX_MSGLEN);
    stretrim(buf);

    if(erno)
    {
        strlcat(buf, ": ", MAX_MSGLEN);
        strncat(buf, strerror(erno), MAX_MSGLEN);
    }

    /* As a precaution */
    buf[MAX_MSGLEN - 1] = 0;

    /* Either to syslog or stderr */
    if(daemonized)
        vsyslog(level, buf, ap);
    else
        vwarnx(buf, ap);
}

/* -----------------------------------------------------------------------------
 * STARTUP
 */

static void
usage()
{
    fprintf(stderr, "usage: rrdbotd [-M] [-c confdir] [-w workdir] [-m mibdir] \n");
    fprintf(stderr, "               [-d level] [-p pidfile] [-r retries] [-t timeout]\n");
    fprintf(stderr, "       rrdbotd -V\n");
    exit(2);
}

static void
version()
{
    printf("rrdbotd (version %s)\n", VERSION);
    printf("   default config directory: %s\n", DEFAULT_CONFIG);
    printf("   default work directory:   %s\n", DEFAULT_WORK);
    printf("   default mib directory:    %s\n", DEFAULT_MIB);
    exit(0);
}

static void
on_quit(int signal)
{
    fprintf(stderr, "rrdbotd: got signal to quit\n");
    server_stop();
}

static void
writepid(const char* pidfile)
{
    FILE* f = fopen(pidfile, "w");
    if(f == NULL)
    {
        log_warn("couldn't open pid file: %s", pidfile);
        return;
    }

    fprintf(f, "%d\n", (int)getpid());
    if(ferror(f))
        log_warn("couldn't write to pid file: %s", pidfile);

    fclose(f);
}

static void
removepid(const char* pidfile)
{
    if(unlink(pidfile) < 0)
    {
        if(errno != ENOENT)
            log_warn("couldn't remove pid file: %s", pidfile);
    }
}

int
main(int argc, char* argv[])
{
	const char** local = NULL;
	int n_local = 0;
    const char* pidfile = NULL;
    int daemonize = 1;
    char ch;
    char* t;

#ifdef TEST
    test(argc, argv);
    return 1;
#endif

    /* Initialize the state stuff */
    memset(&g_state, 0, sizeof(g_state));

    g_state.rrddir = DEFAULT_WORK;
    g_state.confdir = DEFAULT_CONFIG;
    g_state.retries = DEFAULT_RETRIES;
    g_state.timeout = DEFAULT_TIMEOUT;

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "b:c:d:m:Mp:r:t:w:V")) != -1)
    {
        switch(ch)
        {

        /* Bind address */
        case 'b':
            local = xrealloc (local, sizeof (char*) * (n_local + 2));
            local[n_local] = optarg;
            local[++n_local] = NULL;
            break;

        /* Config directory */
        case 'c':
            g_state.confdir = optarg;
            break;

        /* Don't daemonize */
        case 'd':
            daemonize = 0;
            debug_level = strtol(optarg, &t, 10);
            if(*t || debug_level > 4)
                errx(1, "invalid debug log level: %s", optarg);
            debug_level += LOG_ERR;
            break;

        /* mib directory */
        case 'm':
            mib_directory = optarg;
            break;

        /* MIB load warnings */
        case 'M':
            mib_warnings = 1;
            break;

        /* Write out a pid file */
        case 'p':
            pidfile = optarg;
            break;

        /* The number of SNMP retries */
        case 'r':
            g_state.retries = strtol(optarg, &t, 10);
            if(*t || g_state.retries < 0)
                errx(1, "invalid number of retries: %s", optarg);
            break;

        /* The default timeout */
        case 't':
            g_state.timeout = strtol(optarg, &t, 10);
            if(*t || g_state.timeout <= 0)
                errx(1, "invalid timeout (must be above zero): %s", optarg);
            break;

        /* The work directory */
        case 'w':
            g_state.rrddir = optarg;
            break;

        /* Print version number */
        case 'V':
            version();
            break;

        /* Usage information */
        case '?':
        default:
            usage();
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if(argc != 0)
        usage();

    /* No bind addresses specified, use defaults... */
    if (local == NULL) {
        local = xrealloc (local, sizeof (char*) * 3);
        local[0] = "0.0.0.0";
        local[1] = NULL;
#ifdef HAVE_INET6
        local[1] = "::";
        local[2] = NULL;
#endif
    }

    /* The mainloop server */
    server_init();

    /* Parse config and setup SNMP system */
    rb_config_parse();

    /* As an optimization we unload the MIB processing data here */
    mib_uninit();

    /* Rev up the main engine */
    snmp_engine_init (local, g_state.retries);
    rb_poll_engine_init();

    free (local);
    n_local = 0;
    local = NULL;

    if(daemonize)
    {
        /* Fork a daemon nicely */
        if(daemon(0, 0) == -1)
            err(1, "couldn't fork as a daemon");

        log_debug("running as a daemon");
        daemonized = 1;
    }

    /* Setup the Async DNS resolver */
    if(async_resolver_init() < 0)
    {
        log_error("couldn't initialize resolver");
        /* Allow things to proceed without resolver */
    }

    /* Handle signals */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT,  on_quit);
    signal(SIGTERM, on_quit);
    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);

    /* Open the system log */
    openlog("rrdbotd", 0, LOG_DAEMON);

    if(pidfile != NULL)
        writepid(pidfile);

    log_info("rrdbotd version " VERSION " started up");

    /* Now let it go */
    if(server_run() == -1)
        err(1, "critical failure running SNMP engine");

    log_info("rrdbotd stopping");

    /* Cleanups */
    rb_poll_engine_uninit();
    snmp_engine_stop();
    rb_config_free();
    async_resolver_uninit();
    server_uninit();

    if(pidfile != NULL)
        removepid(pidfile);

    return 0;
}
