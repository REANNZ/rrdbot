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
#include <sys/stat.h>
#include <rrd.h>

#include "config-parser.h"

/* -----------------------------------------------------------------------------
 * CONSTANTS
 */

/* The default command line options */
#define DEFAULT_CONFIG      CONF_PREFIX "/rrdbot"
#define DEFAULT_WORK        "/var/db/rrdbot"

#define CONFIG_CREATE   "create"
#define CONFIG_POLL     "poll"
#define CONFIG_INTERVAL "interval"
#define CONFIG_ARCHIVE  "archive"
#define CONFIG_TYPE     "type"
#define CONFIG_MIN      "min"
#define CONFIG_MAX      "max"
#define CONFIG_CF       "cf"

#define VAL_UNKNOWN     "U"
#define VAL_ABSOLUTE    "ABSOLUTE"
#define VAL_GAUGE       "GAUGE"
#define VAL_COUNTER     "COUNTER"
#define VAL_DERIVE      "DERIVE"
#define VAL_COMPUTE     "COMPUTE"
#define VAL_AVERAGE     "AVERAGE"
#define VAL_MIN         "MIN"
#define VAL_MAX         "MAX"
#define VAL_LAST        "LAST"

#define VAL_MINUTE      "minute"
#define VAL_MINUTELY    "minutely"
#define VAL_HOUR        "hour"
#define VAL_HOURLY      "hourly"
#define VAL_DAY         "day"
#define VAL_DAILY       "daily"
#define VAL_WEEK        "week"
#define VAL_WEEKLY      "weekly"
#define VAL_MONTH       "month"
#define VAL_MONTHLY     "monthly"
#define VAL_YEAR        "year"
#define VAL_YEARLY      "yearly"

#define FIELD_VALID     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789."

/* -----------------------------------------------------------------------------
 * DECLARATIONS
 */

typedef struct _field_arg
{
    const char *name;
    const char *dst;
    const char *min;
    const char *max;

    struct _field_arg* next;
}
field_arg;

typedef struct _rra_arg
{
    uint num;
    uint per;
    uint many;

    struct _rra_arg* next;
}
rra_arg;

typedef struct _create_arg
{
    char buf[256];
    struct _create_arg* next;
}
create_arg;

typedef struct _create_ctx
{
    const char* workdir;
    const char* confname;
    uint interval;
    const char *cf;
    int create;
    int skip;

    field_arg* fields;
    rra_arg* rras;
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

static field_arg*
field_for(create_ctx* ctx, char* name)
{
    field_arg* field;

    for(field = ctx->fields; field; field = field->next) {
        if (strcmp(name, field->name) == 0)
            return field;
    }

    field = (field_arg*)calloc(1, sizeof(field_arg));
    if(!field)
        errx(1, "out of memory");

    field->name = name;
    field->dst = VAL_ABSOLUTE;
    field->min = VAL_UNKNOWN;
    field->max = VAL_UNKNOWN;

    field->next = ctx->fields;
    ctx->fields = field;

    return field;
}

static void
context_reset(create_ctx* ctx)
{
    field_arg* field;
    rra_arg* rra;

    while(ctx->fields) {
        field = ctx->fields->next;
        free(ctx->fields);
        ctx->fields = field;
    }

    while(ctx->rras) {
        rra = ctx->rras->next;
        free(ctx->rras);
        ctx->rras = rra;
    }

    ctx->confname = NULL;
    ctx->cf = VAL_AVERAGE;
    ctx->interval = 0;

    ctx->create = 0;
    ctx->skip = 0;
}

/* -----------------------------------------------------------------------------
 * CREATE
 */

static int
mkdir_p(char* path)
{
    struct stat sb;
    int first, last, retval = 0;
    char* p = path;

    /* Skip leading '/'. */
    while(p[0] == '/')
        ++p;

    for(first = 1, last = 0; !last ; ++p)
    {
        if(p[0] == '\0')
            last = 1;
        else if (p[0] != '/')
            continue;
        *p = '\0';
        if(!last && p[1] == '\0')
            last = 1;

        /* Modified by the umask */
        if(mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
        {
            if(errno == EEXIST || errno == EISDIR)
            {
                if(stat(path, &sb) < 0)
                {
                    retval = 1;
                    break;
                }
                else if(!S_ISDIR(sb.st_mode))
                {
                    if (last)
                        errno = EEXIST;
                    else
                        errno = ENOTDIR;
                    retval = 1;
                    break;
                }
            }
            else
            {
                retval = 1;
                break;
            }
        }
        if (!last)
            *p = '/';
    }

    return (retval);
}

static int
create_dir_for_file(const char* path)
{
    char *p = strrchr(path, '/');
    char *dir;
    int r;

    /* No subdirectories, not needed */
    if (!p)
        return 0;

    dir = calloc((p - path) + 1, 1);
    if(!dir)
    {
        errno = ENOMEM;
        return -1;
    }

    memcpy (dir, path, (p - path));
    r = mkdir_p(dir);
    free(dir);

    if(r < 0)
    {
        warnx("couldn't create directory for rrd file: %s", dir);
        return r;
    }

    return r;
}

static int
create_file(create_ctx* ctx, const char* rrd)
{
    create_arg* args = NULL;
    create_arg* arg;
    rra_arg* rra;
    field_arg* field;
    int nargs = 0;
    uint rows, steps;
    int argc, r;
    const char** argv;

    if(!ctx->interval)
    {
        warnx("%s: missing interval option", ctx->confname);
        return -1;
    }

    if(!ctx->fields)
    {
        warnx("%s: no fields defined", ctx->confname);
        return -1;
    }


    /* Build all the RRAs */
    for(rra = ctx->rras; rra; rra = rra->next)
    {
        ASSERT(rra->per);
        ASSERT(rra->num);
        ASSERT(rra->many);

        steps = (rra->per / rra->num) / ctx->interval;
        if(!steps)
        {
            warnx("%s: archive has too many data points for polling interval. ignoring",
                  ctx->confname);
            continue;
        }
        rows = (rra->per * rra->many) / (ctx->interval * steps);

        arg = (create_arg*)xcalloc(sizeof(create_arg));
        snprintf(arg->buf, sizeof(arg->buf), "RRA:%s:0.6:%d:%d",
                 ctx->cf, steps, rows);
        arg->buf[sizeof(arg->buf) - 1] = 0;
        arg->next = args;
        args = arg;
        nargs++;
    }

    if(!nargs)
    {
        warnx("%s: no archives defined", ctx->confname);
        return -1;
    }


    /* Build all the fields */
    for(field = ctx->fields; field; field = field->next)
    {
        ASSERT(field->name);
        arg = (create_arg*)xcalloc(sizeof(create_arg));
        snprintf(arg->buf, sizeof(arg->buf), "DS:%s:%s:%d:%s:%s",
                 field->name, field->dst, ctx->interval * 3, field->min, field->max);
        arg->buf[sizeof(arg->buf) - 1] = 0;
        arg->next = args;
        args = arg;
        nargs++;
    }

    /* And the interval */
    arg = (create_arg*)xcalloc(sizeof(create_arg));
    snprintf(arg->buf, sizeof(arg->buf), "-s%d", ctx->interval);
    arg->buf[sizeof(arg->buf) - 1] = 0;
    arg->next = args;
    args = arg;
    nargs++;

    argv = (const char**)xcalloc(sizeof(char*) * (nargs + 4));

    if(create_dir_for_file(rrd) >= 0)
    {
        argv[0] = "create";
        argv[1] = rrd;
        argv[2] = "-b-1y";  /* Allow stuff up to a year old */
        argc = 3;

        if(!g_print)
            verb("creating rrd with command:");

        if(g_verbose || g_print)
            fprintf(stderr, "# rrd create '%s' -b-1y ", rrd);

        for(arg = args; arg; arg = arg->next)
        {
            argv[argc++] = arg->buf;
            if(g_verbose || g_print)
                fprintf(stderr, "%s ", arg->buf);
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
    }

    /* Some cleanup */
    free(argv);
    while(args)
    {
        arg = args->next;
        free(args);
        args = arg;
    }

    /* We've handled all our own errors */
    return 0;
}

void
check_create_file(create_ctx* ctx)
{
    char rrd[MAXPATHLEN];

    ASSERT(ctx->confname);

    /* No create section, no create */
    if(!ctx->create)
        return;

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

    if(ctx->skip || create_file(ctx, rrd) < 0)
        warnx("skipping rrd creation due to configuration errors: %s", rrd);
}

static int
add_rras(create_ctx* ctx, char* value)
{
    uint per;
    uint num;
    uint many;
    rra_arg* rra;
    char* t;
    char* p;
    char* p2;

    /*
     * Looks like:
     *     10/minute, 10/hour, 10/day, 10/week * 2, 1/month, 5/year
     */

    while(value && *value)
    {
        per = num = 0;
        many = 1;

        /* Skip any delimiters, and parse next */
        value = value + strspn(value, " \t,");
        t = strchr(value, ',');
        if(t)
            *(t++) = 0;

        /* Parse out the number */
        p = strchr(value, '/');
        if(!p)
        {
            warnx("%s: invalid 'archive' option: %s", ctx->confname, value);
            return -1;
        }

        *(p++) = 0;
        num = strtoul(value, &p2, 10);
        if(*p2 || !num)
        {
            warnx("%s: invalid 'archive' factor: %s", ctx->confname, value);
            return -1;
        }


        /* Parse out the time frame */
        p2 = strchr(p, '*');
        if(p2)
            *(p2)++ = 0;

        strtrim(p);
        strlwr(p);

        if(strcmp(p, VAL_MINUTE) == 0 || strcmp(p, VAL_MINUTELY) == 0)
            per = 60;
        else if(strcmp(p, VAL_HOUR) == 0 || strcmp(p, VAL_HOURLY) == 0)
            per = 3600;
        else if(strcmp(p, VAL_DAY) == 0 || strcmp(p, VAL_DAILY) == 0)
            per = 86400;
        else if(strcmp(p, VAL_WEEK) == 0 || strcmp(p, VAL_WEEKLY) == 0)
            per = 604800;
        else if(strcmp(p, VAL_MONTH) == 0 || strcmp(p, VAL_MONTHLY) == 0)
            per = 2592000;
        else if(strcmp(p, VAL_YEAR) == 0 || strcmp(p, VAL_YEARLY) == 0)
            per = 31536000;
        else
        {
            warnx("%s: invalid 'archive' time unit: %s", ctx->confname, p);
            return -1;
        }

        /* Parse out how many */
        if(p2)
        {
            strtrim(p2);
            many = strtoul(p2, &p, 10);
            if(*p || many <= 0)
            {
                warnx("%s: invalid 'archive' count: %s", ctx->confname, p2);
                return -1;
            }
        }

        rra = (rra_arg*)xcalloc(sizeof(rra_arg));
        rra->num = num;
        rra->per = per;
        rra->many = many;
        rra->next = ctx->rras;
        ctx->rras = rra;
        value = t;
    }

    return 0;
}


/* -----------------------------------------------------------------------------
 * CONFIG CALLBACKS
 */

int
cfg_value(const char* filename, const char* header, const char* name,
          char* value, void* data)
{
    create_ctx* ctx = (create_ctx*)data;
    char* suffix;
    char* t;

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
        context_reset(ctx);

        return 0;
    }

    ASSERT(name && value);

    /* [poll] section */
    if(strcmp(header, CONFIG_POLL) == 0)
    {
        /* Interval option */
        if(strcmp(name, CONFIG_INTERVAL) == 0)
        {
            ctx->interval = strtoul(value, &t, 10);
            if(*t || !ctx->interval)
            {
                warnx("%s: invalid 'interval' value: %s", ctx->confname, value);
                ctx->skip = 1;
            }
        }

        /* Ignore other options */
        return 0;
    }

    /* The rest is in the [create] section */
    if(strcmp(header, CONFIG_CREATE) != 0)
        return 0;

    /* Have a [create] section */
    ctx->create = 1;

    /* The cf option */
    if(strcmp(name, CONFIG_CF) == 0)
    {
        strupr(value);
        if(strcmp(value, VAL_AVERAGE) == 0 ||
           strcmp(value, VAL_MIN) == 0 ||
           strcmp(value, VAL_MAX) == 0 ||
           strcmp(value, VAL_LAST) == 0)
        {
            ctx->cf = value;
        }
        else
        {
            warnx("%s: invalid 'cf' value: %s", ctx->confname, value);
            ctx->skip = 1;
        }

        ctx->create = 0;
        return 0;
    }

    /* The archive option */
    if(strcmp(name, CONFIG_ARCHIVE) == 0)
    {
        if(add_rras(ctx, value) < 0)
            ctx->skip = 1;
        return 0;
    }

    /* Try and see if the field has a suffix */
    suffix = strchr(name, '.');
    if(!suffix) /* Ignore unknown options */
        return 0;

    /* Have a [create] section */
    ctx->create = 1;

    *suffix = 0;
    suffix++;

    /* Make sure the field name is good */
    t = (char*)name + strspn(name, FIELD_VALID);
    if(*t)
    {
        warnx("%s: the '%s' field name must only contain characters, digits, underscore and dash",
              ctx->confname, name);
        ctx->skip = 1;
        return 0;
    }

    /* Field type suffix */
    if(strcmp(suffix, CONFIG_TYPE) == 0)
    {
        strupr(value);
        if(strcmp(value, VAL_ABSOLUTE) == 0 ||
           strcmp(value, VAL_COUNTER) == 0 ||
           strcmp(value, VAL_GAUGE) == 0 ||
           strcmp(value, VAL_DERIVE) == 0 ||
           strcmp(value, VAL_COMPUTE) == 0)
        {
            field_for(ctx, (char*)name)->dst = value;
        }
        else
        {
            warnx("%s: invalid field type: %s", ctx->confname, value);
            ctx->skip = 1;
        }

        return 0;
    }

    /* Field minimum */
    if(strcmp(suffix, CONFIG_MIN) == 0)
    {
        strupr(value);
        if(strcmp(value, VAL_UNKNOWN) != 0)
        {
            strtod(value, &t);
            if(*t)
            {
                warnx("%s: invalid field min: %s", ctx->confname, value);
                ctx->skip = 1;
                return 0;
            }
        }

        field_for(ctx, (char*)name)->min = value;
        return 0;
    }

    /* Field maximum */
    if(strcmp(suffix, CONFIG_MAX) == 0)
    {
        strupr(value);
        if(strcmp(value, VAL_UNKNOWN) != 0)
        {
            strtod(value, &t);
            if(*t)
            {
                warnx("%s: invalid field max: %s", ctx->confname, value);
                ctx->skip = 1;
                return 0;
            }
        }

        field_for(ctx, (char*)name)->max = value;
        return 0;
    }

    /* Ignore unknown options */
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

    context_reset(&ctx);

    /*
     * We parse the configuration, this calls cfg_value
     * which will do the actual creation of the files
     */
    if(cfg_parse_dir(confdir, &ctx) == -1)
        exit(1); /* message already printed */

    return 0;
}
