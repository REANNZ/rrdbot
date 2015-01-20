/*
 * Copyright (c) 2004, Stef Walter
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

#ifndef __RRDBOTD_H__
#define __RRDBOTD_H__

#include <stdint.h>
#include <stdarg.h>

#include "asn1.h"
#include "snmp.h"
#include "hash.h"

/* -----------------------------------------------------------------------------
 * DATA
 */

typedef uint64_t mstime;

struct _rb_item;
struct _rb_poller;

/*
 * Note that all the members are either in the config memory
 * or inline. This helps us keep memory management simple.
 */

typedef struct _rb_item
{
    /* The field name, RRD and display */
    const char* field;

    /* The reference value for the field */
    const char* reference;

    /* Connection information */
    const char* community;
    int version;

    /* The oid that we are querying */
    struct asn_oid field_oid;
    int field_request;

    /* Host names, with alternate hosts */
    #define MAX_HOSTNAMES 16
    const char* hostnames[MAX_HOSTNAMES];
    const char* portnum;
    int hostindex;
    int n_hostnames;

    /* Query related stuff */
    int has_query;
    struct asn_oid query_oid;
    const char* query_match;
    int query_matched;
    int query_searched;
    struct asn_oid query_last;
    int query_request;

    /* Book keeping */
    mstime last_request;
    mstime last_polled;

    /* The last value / current request */
    union
    {
        int64_t i_value;
        double f_value;
    } v;

    #define VALUE_UNSET 0
    #define VALUE_REAL  1
    #define VALUE_FLOAT 2
    int vtype;

    /* Pointers to related */
    struct _rb_poller* poller;

    /* Next in list of items */
    struct _rb_item* next;
}
rb_item;

typedef struct _file_path
{
    const char * path;
    /* Next in list of items */
    struct _file_path* next;
}
file_path;

typedef struct _rb_poller
{
    /* The hash key is timeout-interval:conffile or
     * timeout-interval:rrdname in the case of a default rrd path */
    char key[MAXPATHLEN];

    file_path* rrdlist;
    file_path* rawlist;

    mstime interval;
    mstime timeout;

    /* The things to poll. rb_poller owns this list */
    rb_item* items;

    /* Polling is active */
    int polling;

    /* Book keeping */
    mstime last_request;
    mstime last_polled;

    /* Next in list of pollers */
    struct _rb_poller* next;
}
rb_poller;

typedef struct _rb_state
{
    /* Settings from command line */
    const char* confdir;
    const char* rrddir;
    uint retries;
    uint timeout;

    /* All the pollers/hosts */
    rb_poller* polls;

    /* Quick lookups for responses */
    hsh_t* poll_by_key;
}
rb_state;

/* One global rb_state with all the main settings */
extern rb_state g_state;

/* -----------------------------------------------------------------------------
 * CONFIG (config.c)
 */

void rb_config_parse();
void rb_config_free();

/* -----------------------------------------------------------------------------
 * SNMP ENGINE (snmp-engine.c)
 */

void rb_poll_engine_init();
void rb_poll_engine_uninit();

/* -----------------------------------------------------------------------------
 * RRD UPDATE CODE (rrd-update.c)
 */

void rb_rrd_update(rb_poller *poll);

#endif /* __RRDBOTD_H__ */
