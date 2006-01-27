/*
 * Copyright (c) 2005, Nate Nielsen
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
 *  Nate Nielsen <nielsen@memberwebs.com>
 *
 */

#include "usuals.h"
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>

#include "stringx.h"
#include "rrdbotd.h"

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

/* TODO: These should be set from the command line */
static int daemonized = 0;
static int debug_level = LOG_ERR;

/* -----------------------------------------------------------------------------
 * CLEANUP
 */

typedef struct _exit_stack
{
    voidfunc func;
    void* data;

    /* We have a list of these beauties */
    struct _exit_stack* next;
}
exit_stack;

/* Our exit stack */
static exit_stack* atexits = NULL;
static int atexit_registered = 0;

static void
atexit_do_stack(void)
{
    exit_stack* next;
    for(; atexits; atexits = next)
    {
        next = atexits->next;
        (atexits->func)(atexits->data);
        free(atexits);
    }
}

void
rb_atexit(voidfunc func, void* data)
{
    exit_stack* ae;

    ASSERT(func);

    ae = (exit_stack*)calloc(1, sizeof(exit_stack));
    if(ae)
    {
        ae->func = func;
        ae->data = data;
        ae->next = atexits;
        atexits = ae;

        if(!atexit_registered)
            atexit(atexit_do_stack);
    }
}

/* -----------------------------------------------------------------------------
 * LOGGING
 */

static void
vmessage (int level, int err, const char* msg, va_list ap)
{
    #define MAX_MSGLEN  1024
    char buf[MAX_MSGLEN];
    int e = errno;

    if(daemonized) {
        if (level >= LOG_DEBUG)
            return;
    } else {
        if(debug_level < level)
            return;
    }

    ASSERT (msg);
    snprintf(buf, MAX_MSGLEN, "%s%s", msg, err ? ": " : "");

    if(err)
        strncat(buf, strerror(e), MAX_MSGLEN);

    /* As a precaution */
    buf[MAX_MSGLEN - 1] = 0;

    /* Either to syslog or stderr */
    if (daemonized)
        vsyslog (level, buf, ap);
    else
        vwarnx (buf, ap);
}

void
rb_messagex (int level, const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    vmessage(level, 0, msg, ap);
    va_end(ap);
}

void
rb_message (int level, const char* msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    vmessage(level, 1, msg, ap);
    va_end(ap);
}

/* -----------------------------------------------------------------------------
 * STARTUP
 */

static void
usage()
{
    fprintf(stderr, "usage: rrdcollectd [-c confdir] [-w workdir] [-d level] [-p pidfile] [-r retries] [-t timeout]\n");
    fprintf(stderr, "       rrdcollectd -v\n");
    exit(2);
}

#include <values.h>

int
main(int argc, char* argv[])
{
    const char* pidfile = NULL;
    int daemonize = 1;
    char ch;
    char* t;

    /* Initialize the state stuff */
    memset(&g_state, 0, sizeof(g_state));

    g_state.rrddir = DEFAULT_WORK;
    g_state.confdir = DEFAULT_CONFIG;
    g_state.retries = DEFAULT_RETRIES;
    g_state.timeout = DEFAULT_TIMEOUT;

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "c:d:p:r:t:w:v")) != -1)
    {
        switch(ch)
        {

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
        case 'v':
            printf("rrdbotd (version %s)\n", VERSION);
            exit(0);
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

    /* The mainloop server */
    server_init();

    /* Parse config and setup SNMP system */
    rb_config_parse();
    rb_snmp_engine_init();

    if(daemonize)
        warnx("TODO: daemon mode not implemented yet");

    /* Now let it go */
    if(server_run() == -1)
        err(1, "critical failure running SNMP engine");

    /* Cleanups */
    rb_snmp_engine_uninit();
    rb_config_free();
    server_uninit();

    return 0;
}
