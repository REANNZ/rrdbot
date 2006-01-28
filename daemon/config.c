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
#include <syslog.h>
#include <dirent.h>

#include "rrdbotd.h"

/*
 * These routines parse the configuration files and setup the in memory
 * data structures. They're mostly run before becoming a daemon, and just
 * exit on error.
 */

typedef struct _config_ctx
{
    const char* confname;
    char* configmem;
    uint interval;
    uint timeout;
    rb_item* items;
}
config_ctx;

/* -----------------------------------------------------------------------------
 * STRINGS
 */

#define CONFIG_POLL "poll"
#define CONFIG_INTERVAL "interval"
#define CONFIG_TIMEOUT "timeout"
#define CONFIG_FIELD "field."
#define CONFIG_SNMP "snmp"

#define FIELD_VALID "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789."

/* -----------------------------------------------------------------------------
 * CONFIG LOADING
 */

static rb_item*
sort_items_by_host(rb_item *item)
{
    rb_item *sort = NULL;
    rb_item *cur;
    rb_item *it;

    while(item)
    {
        cur = item;
        item = item->next;
        cur->next = NULL;

        /* First item */
        if(!sort)
        {
            sort = cur;
            continue;
        }

        /* Before first item */
        else if(cur->host <= sort->host)
        {
            cur->next = sort;
            sort = cur;
            continue;
        }

        for(it = sort; it->next; it = it->next)
        {
            if(cur->host <= sort->next->host)
                break;
        }

        ASSERT(it);
        cur->next = it->next;
        it->next = cur;
    }

    return sort;
}

static void
config_done(config_ctx* ctx)
{
    char key[MAXPATHLEN];
    rb_item* it;
    rb_poller* poll;
    char *t;

    /* No polling specified */
    if(!ctx->items)
        return;

    /* Make sure we found an interval */
    if(ctx->interval == 0)
        errx(2, "%s: no interval specified", ctx->confname);

    if(ctx->timeout == 0)
        ctx->timeout = g_state.timeout;

    /* And a nice key for lookups */
    snprintf(key, sizeof(key), "%d-%d:%s/%s.rrd", ctx->timeout,
             ctx->interval, g_state.rrddir, ctx->confname);
    key[sizeof(key) - 1] = 0;

    /* See if we have one of these pollers already */
    poll = (rb_poller*)hsh_get(g_state.poll_by_key, key, -1);
    if(!poll)
    {
        poll = (rb_poller*)calloc(1, sizeof(*poll));

        if(!poll || !hsh_set(g_state.poll_by_key, key, -1, poll))
            errx(1, "out of memory");

        strcpy(poll->key, key);
        t = strchr(poll->key, ':');
        ASSERT(t);
        poll->rrdname = t + 1;

        poll->interval = ctx->interval * 1000;
        poll->timeout = ctx->timeout * 1000;

        /* Add it to the main lists */
        poll->next = g_state.polls;
        g_state.polls = poll;
    }

    /* Get the last item and add to the list */
    for(it = ctx->items; it->next; it = it->next)
        it->poller = poll;

    ASSERT(it);
    it->poller = poll;

    /* Add the items to this poller */
    it->next = poll->items;
    poll->items = sort_items_by_host(ctx->items);

    /*
     * This remains allocated for the life of the program as
     * All the configuration strings are in this memory.
     * This allows all the users of these strings not to worry
     * about reallocating or freeing them
     */
    rb_atexit(free, ctx->configmem);
    ctx->configmem = NULL;

    /* Clear current config and get ready for next */
    ctx->items = NULL;
    ctx->interval = 0;


}

static void
parse_uri(char *uri, char** scheme, char** host,
          char** user, char** path, config_ctx* ctx)
{
    /* Copy only for error messages as we mess with original */
    char* copy = strdup(uri);
    char* t;

    *host = NULL;
    *path = NULL;
    *user = NULL;

    *scheme = strsep(&uri, ":");
    if(uri == NULL)
        errx(2, "%s: invalid poll uri (scheme invalid): %s", ctx->confname, copy);

    if((uri[0] != '/' && uri[1] != '/'))
        errx(2, "%s: invalid poll uri (scheme invalid): %s", ctx->confname, copy);

    uri += 2;
    *host = strsep(&uri, "/");
    if(*host[0])
    {
        /* Parse the user name out from the host */
        t = strchr(*host, '@');
        if(t)
        {
            *t = 0;
            *user = *host;
            *host = t + 1;
        }
    }

    if(!*host[0])
        errx(2, "%s: invalid poll uri (no hostname found): %s", ctx->confname, copy);

    if(!uri || !uri[0] || !uri[1])
        errx(2, "%s: invalid poll uri (no pathname found): %s", ctx->confname, copy);

    *path = uri;

    while((*path)[0] == '/')
        (*path)++;

    /* This copy only for error messages */
    free(copy);
}

static rb_item*
parse_item(const char* field, char* uri, config_ctx *ctx)
{
    rb_item *ritem;
    rb_host *rhost;

    char* host;
    char* user;
    char* scheme;
    char* path;

    /* Parse the SNMP URI */
    parse_uri(uri, &scheme, &host, &user, &path, ctx);
    ASSERT(scheme && host && path);

    /* TODO: SNMP version support */

    /* Currently we only support SNMP pollers */
    if(strcmp(scheme, CONFIG_SNMP) != 0)
        errx(2, "%s: invalid poll scheme: %s", ctx->confname, scheme);

    /* TODO: THis code assumes all hosts have the same community
       the lookups below won't work wehn host/community is different */

    /* See if we can find an associated host */
    rhost = (rb_host*)hsh_get(g_state.host_by_name, host, -1);
    if(!rhost)
    {
        /* Make a new one if necessary */
        rhost = (rb_host*)calloc(1, sizeof(*rhost));

        if(!rhost || !hsh_set(g_state.host_by_name, host, -1, rhost))
            errx(1, "out of memory");

        /* TODO: Version support */
        rhost->version = 1;
        rhost->name = host;
        rhost->community = user ? user : "public";

        /* TODO: Eventually resolving should be in a separate thread,
           and done regularly */
        if(sock_any_pton(host, &(rhost->address),
                         SANY_OPT_DEFPORT(161) | SANY_OPT_DEFLOCAL) == -1)
        {
            rb_message(LOG_WARNING, "couldn't resolve host address (ignoring): %s", host);
            free(rhost);
            return;
        }

        /* And add it to the list */
        rhost->next = g_state.hosts;
        g_state.hosts = rhost;
    }

    /* Make a new item */
    ritem = calloc(1, sizeof(*ritem));
    if(!ritem)
        errx(1, "out of memory");

    ritem->rrdfield = field;
    ritem->host = rhost;
    ritem->poller = NULL; /* Set later in config_done */
    ritem->req = NULL;
    ritem->value = RB_UNKNOWN;

    /* And parse the OID */
    if(rb_snmp_parse_mib(path, &(ritem->snmpfield)) == -1)
        errx(2, "%s: invalid MIB: %s", ctx->confname, path);

    rb_messagex(LOG_DEBUG, "parsed MIB into oid: %s -> %s", path,
                asn_oid2str(&(ritem->snmpfield.var)));

    /* And add it to the list */
    ritem->next = ctx->items;
    ctx->items = ritem;
}

static void
config_value(const char* header, const char* name, char* value,
             config_ctx* ctx)
{
    if(strcmp(header, "poll") != 0)
        return;

    if(strcmp(name, CONFIG_INTERVAL) == 0)
    {
        char* t;
        int i;

        if(ctx->interval > 0)
            errx(2, "%s: " CONFIG_INTERVAL " specified twice: %s", ctx->confname, value);

        i = strtol(value, &t, 10);
        if(i < 1 || *t)
            errx(2, "%s: " CONFIG_INTERVAL " must be a number (seconds) greater than zero: %s",
                ctx->confname, value);

        ctx->interval = (uint32_t)i;
    }

    if(strcmp(name, CONFIG_TIMEOUT) == 0)
    {
        char* t;
        int i;

        if(ctx->timeout > 0)
            errx(2, "%s: " CONFIG_TIMEOUT " specified twice: %s", ctx->confname, value);

        i = strtol(value, &t, 10);
        if(i < 1 || *t)
            errx(2, "%s: " CONFIG_TIMEOUT " must be a a number (seconds) greater than zero: %s",
                ctx->confname, value);

        ctx->timeout = (uint32_t)i;
    }

    /* If it starts with "field." */
    if(strncmp(name, CONFIG_FIELD, KL(CONFIG_FIELD)) == 0)
    {
        rb_poller* poll;
        const char* field;
        const char* t;

        /* Check the name */
        field = name + KL(CONFIG_FIELD);
        t = field + strspn(field, FIELD_VALID);
        if(*t)
            err(2, "%s: the '%s' field name must only contain characters, digits, underscore and dash",
                ctx->confname, field);

        /* Parse out the field */
        parse_item(field, value, ctx);
    }
}

/* -----------------------------------------------------------------------------
 * CONFIG FILES
 */

static char*
read_config_file(const char* configfile)
{
    char* config = NULL;
    FILE* f = NULL;
    long len;

    ASSERT(configfile);

    f = fopen(configfile, "r");
    if(f == NULL)
        err(1, "couldn't open config file: %s", configfile);

    /* Figure out size */
    if(fseek(f, 0, SEEK_END) == -1 || (len = ftell(f)) == -1 || fseek(f, 0, SEEK_SET) == -1)
        err(1, "couldn't seek config file: %s", configfile);

    if((config = (char*)malloc(len + 2)) == NULL)
        errx(1, "out of memory");

    /* And read in one block */
    if(fread(config, 1, len, f) != len)
        err(1, "couldn't read config file: %s", configfile);

    fclose(f);

    /* Null terminate the data */
    config[len] = '\n';
    config[len + 1] = 0;

    /* Remove nasty dos line endings */
    strcln(config, '\r');

    rb_messagex(LOG_DEBUG, "read config file: %s", configfile);
    return config;
}

static void
parse_config_file(const char* configfile, config_ctx *ctx)
{
    char* name = NULL;
    char* value = NULL;
    char* config;
    char* next;
    char* header;
    char* p;
    char* t;
    int pos;

    config = read_config_file(configfile);
    ctx->configmem = config;
    next = config;

    /* Go through lines and process them */
    while((t = strchr(next, '\n')) != NULL)
    {
        *t = 0;
        p = next; /* Do this before cleaning below */
        next = t + 1;

        t = strbtrim(p);

        /* Continuation line (had spaces at start) */
        if(p < t && *t)
        {
            if(!value)
                errx(2, "%s: invalid continuation in config: %s",
                     ctx->confname, p);

            /* Calculate the end of the current value */
            t = value + strlen(value);
            ASSERT(t < p);

            /* Continuations are separated by spaces */
            *t = ' ';
            t++;

            continue;
        }

        // No continuation hand off value if necessary
        if(name && value)
        {
            rb_messagex(LOG_DEBUG, "config: %s: [%s] %s = %s",
                        ctx->confname, header, name, value);
            config_value(header, name, value, ctx);
        }

        name = NULL;
        value = NULL;

        /* Empty lines / comments at start / comments without continuation */
        if(!*t || *p == '#')
            continue;

        /* A header */
        if(*p == '[')
        {
            t = p + strcspn(p, "]");
            if(!*t || t == p + 1)
                errx(2, "%s: invalid config header: %s", ctx->confname, p);

            *t = 0;
            header = strtrim(p + 1);
            continue;
        }

        /* Look for the break between name = value on the same line */
        t = p + strcspn(p, ":=");
        if(!*t)
            errx(2, "%s: invalid config line: %s", ctx->confname, p);

        /* Null terminate and split value part */
        *t = 0;
        t++;

        name = strtrim(p);
        value = strtrim(t);
    }

    if(name && value)
    {
        rb_messagex(LOG_DEBUG, "config: %s: [%s] %s = %s",
                    ctx->confname, header, name, value);
        config_value(header, name, value, ctx);
    }

    config_done(ctx);

    /* If nobody claimed this memory then we don't need to keep it around */
    if(ctx->configmem)
        free(ctx->configmem);
    ctx->configmem = NULL;
}

void
rb_config_parse()
{
    char configfile[MAXPATHLEN];
    struct dirent* dire;
    config_ctx ctx;
    DIR* dir;

    /* Setup the hash tables properly */
    g_state.poll_by_key = hsh_create();
    g_state.host_by_name = hsh_create();

    dir = opendir(g_state.confdir);
    if(!dir)
        err(1, "couldn't list config directory: %s", g_state.confdir);

    while((dire = readdir(dir)) != NULL)
    {
        if(dire->d_type != DT_REG && dire->d_type != DT_LNK)
            continue;

        /* Build a happy path name */
        snprintf(configfile, MAXPATHLEN, "%s/%s", g_state.confdir, dire->d_name);
        configfile[MAXPATHLEN - 1] = 0;

        memset(&ctx, 0, sizeof(ctx));
        ctx.confname = dire->d_name;

        parse_config_file(configfile, &ctx);
    }

    if(!g_state.polls)
        errx(1, "no config files found in config directory: %s", g_state.confdir);

    closedir(dir);
}

/* -----------------------------------------------------------------------------
 * FREEING MEMORY
 */

static void
free_items(rb_item* item)
{
    rb_item* next;
    for(; item; item = next)
    {
        next = item->next;
        free(item);
    }
}

static void
free_hosts(rb_host* host)
{
    rb_host* next;
    for(; host; host = next)
    {
        next = host->next;
        free(host);
    }
}

static void
free_pollers(rb_poller* poll)
{
    rb_poller* next;
    for(; poll; poll = next)
    {
        free_items(poll->items);

        next = poll->next;
        free(poll);
    }

}

void
rb_config_free()
{
    hsh_free(g_state.poll_by_key);
    hsh_free(g_state.host_by_name);

    free_hosts(g_state.hosts);

    /* Note that rb_item's are owned by pollers */
    free_pollers(g_state.polls);
}
