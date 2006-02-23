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
#include <err.h>

#include <rrd.h>

#include "config-parser.h"

/* -----------------------------------------------------------------------------
 * CONSTANTS
 */

/* The default command line options */
#define DEFAULT_CONFIG      CONF_PREFIX "/rrdbot"
#define DEFAULT_WORK        "/var/db/rrdbot"

#define CONFIG_CREATE   "create"
#define CONFIG_RRA      "rra"
#define CONFIG_FIELD    "field."

#define FIELD_VALID     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789."

/* -----------------------------------------------------------------------------
 * DECLARATIONS
 */

typedef struct _create_arg
{
    char* def;
    struct _create_arg* next;
}
create_arg;

typedef struct _create_ctx
{
    const char* workdir;
    const char* confname;
    int skip;
    create_arg* args;
}
create_ctx;

/* Wether to print out status updates */
static int g_verbose = 0;
static int g_print = 0;

/* -----------------------------------------------------------------------------
 * HELPERS
 */

void
verb(const char* fmt, ...)
{
    va_list va;

    if(!g_verbose)
        return;

    va_start(va, fmt);
    vwarnx(fmt, va);
    va_end(va);
}

/* -----------------------------------------------------------------------------
 * CREATE
 */

void
create_file(create_ctx* ctx, const char* rrd)
{
    create_arg* arg;
    int num = 0;
    int argc, r;
    const char** argv;

    for(arg = ctx->args; arg; arg = arg->next)
        num++;

    argv = (const char**)xcalloc(sizeof(char*) * (num + 5));

    argv[0] = "create";
    argv[1] = rrd;
    argv[2] = "-b-1y";  /* Allow stuff up to a year old */
    argv[3] = "-s10";   /* Up to 10 second resolution */
    argc = 4;

    if(!g_print)
        verb("creating rrd with command:");

    if(g_verbose || g_print)
        fprintf(stderr, "# rrd create '%s' -b-1y -s10 ", rrd);

    for(arg = ctx->args; arg; arg = arg->next)
    {
        argv[argc++] = arg->def;

        if(g_verbose || g_print)
            fprintf(stderr, "%s ", arg->def);
    }

    if(g_verbose || g_print)
        fprintf(stderr, "\n");

    if(!g_print)
    {
        /* Always have to clear before calling rrdtool. klunky :( */
        optind = 0;
        opterr = 0;

        rrd_clear_error();
        r = rrd_create(argc, (char**)argv);

        if(r != 0)
            warnx("couldn't create rrd file: %s: %s", rrd, rrd_get_error());
        else if(!g_print)
            verb("created rrd: %s", rrd);
    }

    free(argv);
}

void
check_create_file(create_ctx* ctx)
{
    char rrd[MAXPATHLEN];

    ASSERT(ctx->confname);

    snprintf(rrd, sizeof(rrd), "%s/%s.rrd", ctx->workdir, ctx->confname);
    rrd[sizeof(rrd) - 1] = 0;

    /* Make sure it exists */
    if(access(rrd, F_OK) == 0)
    {
        verb("rrd file already exists, skipping: %s", rrd);
        return;
    }
    else if(errno != ENOENT)
    {
        warn("couldn't check rrd file: %s", rrd);
        return;
    }

    if(ctx->skip)
    {
        warnx("skipping rrd creation due to configuration errors: %s", rrd);
        return;
    }

    create_file(ctx, rrd);
}

static void
add_rras(create_ctx* ctx, char* value)
{
    const char rrafmt[] = "RRA:%s";
    create_arg* arg;
    char* def;
    char* t;
    int len;

    while(value && *value)
    {
        t = strchr(value, ' ');
        if(t)
            *(t++) = 0;

        len = strlen(rrafmt) + strlen(value) + 1;
        def = (char*)xcalloc(len);
        snprintf(def, len, rrafmt, strtrim(value));
        def[len - 1] = 0;

        arg = (create_arg*)xcalloc(sizeof(create_arg));
        arg->def = def;
        arg->next = ctx->args;
        ctx->args = arg;

        value = t;
    }
}

static void
add_field(create_ctx* ctx, const char* field, char* value)
{
    const char dsfmt[] = "DS:%s:%s";
    create_arg* arg;
    char* def;
    int len;

    len = strlen(dsfmt) + strlen(field) + strlen(value) + 1;
    def = (char*)xcalloc(len);
    snprintf(def, len, dsfmt, field, value);
    def[len - 1] = 0;

    arg = (create_arg*)xcalloc(sizeof(create_arg));
    arg->def = def;
    arg->next = ctx->args;
    ctx->args = arg;
}


/* -----------------------------------------------------------------------------
 * CONFIG CALLBACKS
 */

int
cfg_value(const char* filename, const char* header, const char* name,
          char* value, void* data)
{
    create_ctx* ctx = (create_ctx*)data;
    create_arg* arg;

    ASSERT(filename);
    ASSERT(ctx);

    if(!ctx->confname)
        ctx->confname = filename;

    /* Called like this after each config file */
    if(!header)
    {
        /* Create this file (if necessary) */
        check_create_file(ctx);

        /* Do cleanup */
        ctx->confname = NULL;

        while(ctx->args)
        {
            arg = ctx->args->next;
            free(ctx->args->def);
            free(ctx->args);
            ctx->args = arg;
        }

        ctx->skip = 0;
        return 0;
    }

    ASSERT(name && value);

    /* Only process this section */
    if(strcmp(header, CONFIG_CREATE) != 0)
        return 0;

    /* The rra option */
    if(strcmp(name, CONFIG_RRA) == 0)
        add_rras(ctx, value);

    /* If it starts with "field." */
    else if(strncmp(name, CONFIG_FIELD, KL(CONFIG_FIELD)) == 0)
    {
        const char* field;
        const char* t;

        /* Check the name */
        field = name + KL(CONFIG_FIELD);
        t = field + strspn(field, FIELD_VALID);
        if(*t)
        {
            warnx("%s: the '%s' field name must only contain characters, digits, underscore and dash",
                  ctx->confname, field);
            ctx->skip = 1;
            return 0;
        }

        add_field(ctx, field, value);
    }

    return 0;
}

int
cfg_error(const char* filename, const char* errmsg, void* data)
{
    create_ctx* ctx = (create_ctx*)data;

    /* Skip the file on errors */
    ctx->skip = 1;

    warnx("%s", errmsg);
    return 0;
}


/* -----------------------------------------------------------------------------
 * STARTUP
 */

static void
usage()
{
    fprintf(stderr, "usage: rrdbot-create [-vn] [-c confdir] [-w workdir]\n");
    fprintf(stderr, "       rrdbot-create -V\n");
    exit(2);
}

static void
version()
{
    printf("rrdbot-create (version %s)\n", VERSION);
    printf("   default config directory: %s\n", DEFAULT_CONFIG);
    printf("   default work directory:   %s\n", DEFAULT_WORK);
    exit(0);
}

int
main(int argc, char* argv[])
{
    const char* confdir = DEFAULT_CONFIG;
    create_ctx ctx;
    char ch;

    memset(&ctx, 0, sizeof(ctx));
    ctx.workdir = DEFAULT_WORK;

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "c:nw:vV")) != -1)
    {
        switch(ch)
        {

        /* Config directory */
        case 'c':
            confdir = DEFAULT_CONFIG;
            break;

        /* Only print commands */
        case 'n':
            g_print = 1;
            break;

        /* Be verbose */
        case 'v':
            g_verbose = 1;
            break;

        /* Print version number */
        case 'V':
            version();
            break;

        /* The work directory */
        case 'w':
            ctx.workdir = optarg;
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


    /*
     * We parse the configuration, this calls cfg_value
     * which will do the actual creation of the files
     */
    if(cfg_parse_dir(confdir, &ctx) == -1)
        exit(1); /* message already printed */

    return 0;
}
