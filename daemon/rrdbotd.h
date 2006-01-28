/*
 * Copyright (c) 2004, Nate Nielsen
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

#ifndef __RRDBOTD_H__
#define __RRDBOTD_H__

#include <values.h>
#include <stdint.h>
#include <stdarg.h>

#include "asn1.h"
#include "snmp.h"
#include "sock-any.h"
#include "hash.h"

/* -----------------------------------------------------------------------------
 * DATA
 */

typedef uint64_t mstime;
#define RB_UNKNOWN -DBL_MAX

struct _rb_item;
struct _rb_poller;
struct _rb_host;
struct _rb_request;

/*
 * Note that all the members are either in the config memory
 * or inline. This helps us keep memory management simple.
 */

typedef struct _rb_item
{
    struct _rb_request* req;

    /* Specific to this item */
    const char* rrdfield;
    struct snmp_value snmpfield;

    /* The last value / current request */
    double value;

    /* Pointers to related */
    const struct _rb_poller* poller;
    const struct _rb_host* host;

    /* Next in list of items */
    struct _rb_item* next;
}
rb_item;

typedef struct _rb_host
{
    const char* name;
    const char* community;
    int version;

    /* Host resolving and book keeping */
    struct sockaddr_any address;
    mstime interval;
    mstime last_resolved;

    /* Next in list of hosts */
    struct _rb_host* next;
}
rb_host;

typedef struct _rb_poller
{
    /* The hash key is interval-timeout:rrdname */
    char key[MAXPATHLEN];

    /* This points into the memory above */
    const char* rrdname;

    mstime interval;
    mstime timeout;

    /* The things to poll. rb_poller owns this list */
    rb_item* items;

    /* Book keeping */
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
    rb_host* hosts;

    /* Quick lookups for responses */
    hsh_t* poll_by_key;
    hsh_t* host_by_name;
}
rb_state;

/* One global rb_state with all the main settings */
extern rb_state g_state;

/* -----------------------------------------------------------------------------
 * UTILITIES (rrdbotd.c)
 */

void rb_messagex(int level, const char* msg, ...);
void rb_message(int level, const char* msg, ...);
void rb_vmessage(int level, int err, const char* msg, va_list ap);

/* -----------------------------------------------------------------------------
 * CONFIG (config.c)
 */

void rb_config_parse();
void rb_config_free();

/* -----------------------------------------------------------------------------
 * SNMP HELPERS (snmp-help.c)
 */

int rb_snmp_parse_mib(const char* oid, struct snmp_value* value);

/* -----------------------------------------------------------------------------
 * SNMP ENGINE (snmp-engine.c)
 */

void rb_snmp_engine_init();
void rb_snmp_engine_uninit();

/* -----------------------------------------------------------------------------
 * RRD UPDATE CODE (rrd-update.c)
 */

void rb_rrd_update(rb_poller *poll);

/* -----------------------------------------------------------------------------
 * MIB PARSING
 */

typedef void* mib_node;

void rb_mib_init(const char* dir, int warnings);
mib_node rb_mib_lookup(const char* match);
int rb_mib_subid(mib_node n, const char* name);
void rb_mib_oid(mib_node n, struct asn_oid* oid);
mib_node rb_mib_node(struct asn_oid* oid);
void rb_mib_uninit();

#endif /* __RRDBOTD_H__ */
