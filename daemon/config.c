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
#include <dirent.h>
#include <string.h>
#include <err.h>

#include <mib/mib-parser.h>

#include "rrdbotd.h"
#include "config-parser.h"

/*
 * These routines parse the configuration files and setup the in memory
 * data structures. They're mostly run before becoming a daemon, and just
 * exit on error.
 */

typedef struct _config_ctx
{
    const char* confname;
    const char* rrdname;
    uint interval;
    uint timeout;
    rb_item* items;
}
config_ctx;

/* -----------------------------------------------------------------------------
 * STRINGS
 */

#define CONFIG_GENERAL "general"
#define CONFIG_RRD "rrd"
#define CONFIG_POLL "poll"
#define CONFIG_INTERVAL "interval"
#define CONFIG_TIMEOUT "timeout"
#define CONFIG_SOURCE "source"

#define CONFIG_SNMP "snmp"
#define CONFIG_SNMP2 "snmp2"
#define CONFIG_SNMP2C "snmp2c"

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
    if(ctx->items)
    {
        /* Make sure we found an interval */
        if(ctx->interval == 0)
            errx(2, "%s: no interval specified", ctx->confname);

        if(ctx->timeout == 0)
            ctx->timeout = g_state.timeout;

        /* And a nice key for lookups */
        if(ctx->rrdname)
            snprintf(key, sizeof(key), "%d-%d:%s", ctx->timeout, ctx->interval,
                     ctx->rrdname);
        else
            snprintf(key, sizeof(key), "%d-%d:%s/%s.rrd", ctx->timeout,
                     ctx->interval, g_state.rrddir, ctx->confname);
        key[sizeof(key) - 1] = 0;

        /* See if we have one of these pollers already */
        poll = (rb_poller*)hsh_get(g_state.poll_by_key, key, -1);
        if(!poll)
        {
            poll = (rb_poller*)xcalloc(sizeof(*poll));

            strcpy(poll->key, key);
            t = strchr(poll->key, ':');
            ASSERT(t);
            poll->rrdname = t + 1;

            poll->interval = ctx->interval * 1000;
            poll->timeout = ctx->timeout * 1000;

            /* Add it to the main lists */
            poll->next = g_state.polls;
            g_state.polls = poll;

            /* And into the hashtable */
            if(!hsh_set(g_state.poll_by_key, poll->key, -1, poll))
                errx(1, "out of memory");
        }

        /* Get the last item and add to the list */
        for(it = ctx->items; it->next; it = it->next)
            it->poller = poll;

        ASSERT(it);
        it->poller = poll;

        /* Add the items to this poller */
        it->next = poll->items;
        poll->items = sort_items_by_host(ctx->items);
    }

    /*
     * This remains allocated for the life of the program as
     * All the configuration strings are in this memory.
     * This allows all the users of these strings not to worry
     * about reallocating or freeing them
     */

    /* Clear current config and get ready for next */
    ctx->items = NULL;
    ctx->interval = 0;
    ctx->timeout = 0;
}

static rb_item*
parse_item(const char* field, char* uri, config_ctx *ctx)
{
    char key[128];
    rb_item *ritem;
    rb_host *rhost;
    int r;

    enum snmp_version version;
    const char *msg;
    char* copy;
    char* scheme;
    char* host;
    char* user;
    char* path;

    /* Parse the SNMP URI */
    copy = strdup(uri);
    msg = cfg_parse_uri(uri, &scheme, &host, &user, &path);
    if(msg)
        errx(2, "%s: %s: %s", ctx->confname, msg, copy);
    free(copy);

    ASSERT(host && path);

    /* Currently we only support SNMP pollers */
    msg = cfg_parse_scheme(scheme, &version);
    if(msg)
        errx(2, "%s: %s", msg, scheme);

    /*
     * Build a lookup key. We can only combine requests for the same
     * host when the version and community match.
     */
    user = user ? user : "public";
    snprintf(key, sizeof(key), "%d:%s:%s", version, host, user);
    key[sizeof(key) - 1] = 0;

    /* See if we can find an associated host */
    rhost = (rb_host*)hsh_get(g_state.host_by_key, key, -1);
    if(!rhost)
    {
        /* Make a new one if necessary */
        rhost = (rb_host*)xcalloc(sizeof(*rhost));

        rhost->version = version;
        rhost->hostname = host;
        rhost->community = user;
        rhost->is_resolved = 1;
        rhost->resolve_interval = 0;
        rhost->last_resolved = 0;

        /* Try and resolve the DNS name */
        r = sock_any_pton(host, &(rhost->address),
                         SANY_OPT_DEFPORT(161) | SANY_OPT_DEFLOCAL | SANY_OPT_NORESOLV);

        if(r == -1)
        {
            rb_message(LOG_WARNING, "couldn't parse host address (ignoring): %s", host);
            free(rhost);
            return NULL;
        }

        /*
         * If we got back SANY_AF_DNS, then it needs resolving. The actual
         * interval and stuff are worked out in rb_config_parse() once all
         * the hosts, polls etc... have been parsed.
         */
        if(r == SANY_AF_DNS)
            rhost->is_resolved = 0;

        /* And add it to the list */
        rhost->next = g_state.hosts;
        g_state.hosts = rhost;

        /* And into the hash table */
        if(!hsh_set(g_state.host_by_key, rhost->key, -1, rhost))
            errx(1, "out of memory");
    }

    /* Make a new item */
    ritem = (rb_item*)xcalloc(sizeof(*ritem));
    ritem->rrdfield = field;
    ritem->host = rhost;
    ritem->poller = NULL; /* Set later in config_done */
    ritem->req = NULL;
    ritem->vtype = VALUE_UNSET;

    /* And parse the OID */
    ritem->snmpfield.syntax = SNMP_SYNTAX_NULL;
    memset(&(ritem->snmpfield.v), 0, sizeof(ritem->snmpfield.v));
    if(mib_parse(path, &(ritem->snmpfield.var)) == -1)
        errx(2, "%s: invalid MIB: %s", ctx->confname, path);

    rb_messagex(LOG_DEBUG, "parsed MIB into oid: %s -> %s", path,
                asn_oid2str(&(ritem->snmpfield.var)));

    /* And add it to the list */
    ritem->next = ctx->items;
    ctx->items = ritem;

    return ritem;
}

static void
config_value(const char* header, const char* name, char* value,
             config_ctx* ctx)
{
    char* suffix;

    if(strcmp(header, CONFIG_GENERAL) == 0)
    {
        if(strcmp(name, CONFIG_RRD) == 0)
            ctx->rrdname = value;

        /* Ignore other [general] options */
        return;
    }

    if(strcmp(header, CONFIG_POLL) != 0)
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
        return;
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
        return;
    }

    /* Parse out suffix */
    suffix = strchr(name, '.');
    if(!suffix) /* Ignore unknown options */
        return;

    *suffix = 0;
    suffix++;

    /* If it starts with "field." */
    if(strcmp(suffix, CONFIG_SOURCE) == 0)
    {
        const char* t;

        /* Check the name */
        t = name + strspn(name, FIELD_VALID);
        if(*t)
            errx(2, "%s: the '%s' field name must only contain characters, digits, underscore and dash",
                 ctx->confname, name);

        /* Parse out the field */
        parse_item(name, value, ctx);
    }
}

void
rb_config_parse()
{
    config_ctx ctx;
    rb_poller* poll;

    /* Setup the hash tables properly */
    g_state.poll_by_key = hsh_create();
    g_state.host_by_key = hsh_create();

    memset(&ctx, 0, sizeof(ctx));

    if(cfg_parse_dir(g_state.confdir, &ctx) == -1)
        exit(2); /* message already printed */

    if(!g_state.polls)
        errx(1, "no config files found in config directory: %s", g_state.confdir);

    /* Organize the async resolve intervals */
    for(poll = g_state.polls; poll; poll = poll->next)
    {
        rb_item *item;
        mstime resint;

        /* When less than three minutes, resolve once per minute */
        if(poll->interval <= 180000)
            resint = 60000;

        /* When between 3 and 10 minutes resolve once per cycle */
        else if(poll->interval <= 600000)
            resint = poll->interval;

        /* Otherwise resolve thrice per cycle */
        else
            resint = poll->interval / 3;

        for(item = poll->items; item; item = item->next)
        {
            /* The lowest interval (since hosts can be shared by pollers) wins */
            if(!item->host->is_resolved && item->host->resolve_interval < resint)
            {
                rb_host* host = (rb_host*)item->host;
                host->resolve_interval = resint;
            }
        }
    }
}

/* -----------------------------------------------------------------------------
 * CONFIG CALLBACKS
 */

int
cfg_value(const char* filename, const char* header, const char* name,
          char* value, void* data)
{
    config_ctx* ctx = (config_ctx*)data;

    ASSERT(filename);
    ASSERT(ctx);

    /* A little setup where necessary */
    if(!ctx->confname)
        ctx->confname = filename;

    /* Called like this after each file */
    if(!header)
    {
        config_done(ctx);
        ctx->confname = NULL;
        return 0;
    }

    ASSERT(ctx->confname);
    ASSERT(name && value && header);

    rb_messagex(LOG_DEBUG, "config: %s: [%s] %s = %s",
                ctx->confname, header, name, value);

    config_value(header, name, value, ctx);

    return 0;
}

int
cfg_error(const char* filename, const char* errmsg, void* data)
{
    /* Just exit on errors */
    errx(2, "%s", errmsg);
    return 0;
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
    hsh_free(g_state.host_by_key);

    free_hosts(g_state.hosts);

    /* Note that rb_item's are owned by pollers */
    free_pollers(g_state.polls);
}
