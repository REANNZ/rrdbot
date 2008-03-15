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

#include "log.h"
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
        poll->items = ctx->items;
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

static void
parse_hosts (rb_item *item, char *host, config_ctx *ctx)
{
	char *x;

	for(;;) {
		x = strchr (host, ',');
		if (x)
			*x = 0;

		if (*host) {
			if (item->n_hostnames >= MAX_HOSTNAMES) {
				log_warnx ("%s: too many host names: %s", ctx->confname, host);
				break;
			}

			item->hostnames[item->n_hostnames] = host;
			item->n_hostnames++;
		}

		if (!x)
			break;

		host = x + 1;
	}

	/* Default to localhost for a host name */
	if (!item->n_hostnames) {
		log_warnx ("no host found in URI, defaulting to localhost");
		item->n_hostnames = 1;
		item->hostnames[0] = "localhost";
	}

	item->hostindex = 0;
}

static void
parse_query (rb_item *item, char *query, config_ctx *ctx)
{
	char *name, *value;
	const char *msg;

	/* Parse the query if it exists */
	if (!query)
		return;

	msg = cfg_parse_query (query, &name, &value, &query);
	if (msg)
		errx (2, "%s: %s", ctx->confname, msg);

	if (query && *query)
		log_warnx ("%s: only using first query argument in snmp URI", ctx->confname);

	item->has_query = 1;

	/* And parse the query OID */
	if (mib_parse (name, &(item->query_oid)) == -1)
		errx (2, "%s: invalid MIB: %s", ctx->confname, name);
	if (item->query_oid.len >= ASN_MAXOIDLEN)
		errx (2, "request OID is too long");

	log_debug ("parsed MIB into oid: %s -> %s", name,
	           asn_oid2str (&item->query_oid));

	item->query_match = value;
	memset (&item->query_last, 0, sizeof (item->query_last));
	item->query_matched = 0;
	item->query_searched = 0;
}

static rb_item*
parse_item (const char *field, char *uri, config_ctx *ctx)
{
	rb_item *item;
	enum snmp_version version;
	const char *msg;
	char *copy;
	char *scheme, *host, *user, *path, *query;

	/* Parse the SNMP URI */
	copy = strdup (uri);
	msg = cfg_parse_uri (uri, &scheme, &host, &user, &path, &query);
	if (msg)
		errx(2, "%s: %s: %s", ctx->confname, msg, copy);
	free (copy);

	ASSERT (host && path);

	/* Currently we only support SNMP pollers */
	msg = cfg_parse_scheme (scheme, &version);
	if (msg)
		errx (2, "%s: %s: %s", ctx->confname, msg, scheme);

	/* Make a new item */
	item = (rb_item*)xcalloc (sizeof (*item));
	item->field = field;
	item->community = user ? user : "public";
	item->version = version;

	item->poller = NULL; /* Set later in config_done */
	item->vtype = VALUE_UNSET;

	/* Parse the hosts, query */
	parse_hosts (item, host, ctx);
	parse_query (item, query, ctx);

	/* And parse the main field OID */
	if (mib_parse (path, &(item->field_oid)) == -1)
		errx (2, "%s: invalid MIB: %s", ctx->confname, path);
	if (item->field_oid.len >= ASN_MAXOIDLEN)
		errx (2, "request OID is too long");

	log_debug ("parsed MIB into oid: %s -> %s", path,
	           asn_oid2str (&item->field_oid));

	/* And add it to the list */
	item->next = ctx->items;
	ctx->items = item;

	return item;
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

    /* Setup the hash tables properly */
    g_state.poll_by_key = hsh_create();

    memset(&ctx, 0, sizeof(ctx));

    if(cfg_parse_dir(g_state.confdir, &ctx) == -1)
        exit(2); /* message already printed */

    if(!g_state.polls)
        errx(1, "no config files found in config directory: %s", g_state.confdir);
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

    log_debug("config: %s: [%s] %s = %s", ctx->confname, header, name, value);

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

    /* Note that rb_item's are owned by pollers */
    free_pollers(g_state.polls);
}
