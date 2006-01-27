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

/*
 * This file is not compiled on it's own. It's included into parse.c
 * and provides compatibility definitions for making it work without
 * the rest of net-snmp
 */

#include "usuals.h"
#include "rrdbotd.h"

static int with_warnings = 0;
static int initialized = 0;

/* -----------------------------------------------------------------------------
 * DEFINITIONS
 */

#define FALSE 0
#define TRUE 1

/* No need to implement these */
#define DEBUGMSGTL
#define set_function(tp)

/* Just return the tree head */
#define get_tree_head()     \
    (tree_head)

#define snmp_get_do_debugging()     (0)

typedef u_long oid;

#define NETSNMP_DS_LIBRARY_ID           0
#define NETSNMP_DS_LIB_MIB_WARNINGS     1
#define NETSNMP_DS_LIB_MIB_REPLACE      2
#define NETSNMP_DS_LIB_SAVE_MIB_DESCRS  3
#define NETSNMP_DS_LIB_MIB_ERRORS       4
#define NETSNMP_DS_LIB_MIB_PARSE_LABEL  5
#define NETSNMP_DS_LIB_MIB_COMMENT_TERM 6

#define netsnmp_ds_get_boolean(d, v) \
    netsnmp_ds_get_int(d, v)

static int
netsnmp_ds_get_int(int dummy, int var)
{
    switch(var)
    {
    case NETSNMP_DS_LIB_MIB_WARNINGS:
        return with_warnings;
    case NETSNMP_DS_LIB_MIB_REPLACE:
        return 0;
    case NETSNMP_DS_LIB_SAVE_MIB_DESCRS:
        return 0;
    case NETSNMP_DS_LIB_MIB_PARSE_LABEL:
        return 1;
    case NETSNMP_DS_LIB_MIB_COMMENT_TERM:
        return 0;
    default:
        return 0;
    }
}

#define netsnmp_ds_set_int(a, b, c)
#define netsnmp_ds_set_boolean(a, b, c)
#define netsnmp_ds_toggle_boolean(a, b)

static int
snmp_log(int level, const char* msg, ...)
{
    va_list ap;

    if(level >= LOG_WARNING && !with_warnings)
        return;

    va_start(ap, msg);
    rb_vmessage(level, 0, msg, ap);
    va_end(ap);
}

/* Only used to open files */
static int
snmp_log_perror(const char* file)
{
    rb_message(LOG_ERR, "couldn't open file: %s", file);
}

#define SNMP_FREE(s)           do { if (s) { free((void *)s); s=NULL; } } while(0)

/* -----------------------------------------------------------------------------
 * RRDBOT GLUE CODE
 */

static void
clear_tree_flags(struct tree *tp)
{
    for( ; tp; tp = tp->next_peer)
    {
        tp->reported = 0;
        if(tp->child_list)
            clear_tree_flags(tp->child_list);
    }
}

void
rb_mib_init(int warnings)
{
    if(initialized)
        return;

    with_warnings = warnings;

    init_mib_internals();
    add_mibdir("/usr/share/snmp/mibs");
    read_all_mibs();

    rb_messagex(LOG_DEBUG, "loaded all MIB files");
    initialized = 1;
}

mib_node
rb_mib_lookup(const char* match)
{
    extern struct tree *tree_head;
    struct tree* mib;

    ASSERT(initialized);

    clear_tree_flags(tree_head);
    mib = find_best_tree_node(match, NULL, NULL);
    return (mib_node)mib;
}

int
rb_mib_subid(mib_node n, const char* name)
{
    struct tree *parent = (struct tree*)n;
    struct tree *tp = NULL;

    ASSERT(initialized);

    for(tp = parent->child_list; tp; tp = tp->next_peer)
    {
        if(strcasecmp(name, tp->label) == 0)
            return tp->subid;
    }

    return -1;
}

void
rb_mib_oid(mib_node n, struct asn_oid* oid)
{
    struct tree* mib = (struct tree*)n;
    struct tree *tp = NULL;
    int len;

    ASSERT(mib);

    /* Figure out where to start */
    len = 0;
    for(tp = mib; tp; tp = tp->parent)
        len++;

    oid->len = len;
    for(tp = mib; tp; tp = tp->parent)
        oid->subs[--len] = tp->subid;
}

mib_node
rb_mib_node(struct asn_oid* oid)
{
    extern struct tree *tree_head;
    struct tree *tp = NULL;
    asn_subid_t subid;
    int i;

    ASSERT(initialized);

    for(i = 0, tp = tree_head; tp && i < oid->len;
        i++, tp = tp ? tp->child_list : NULL)
    {
        subid = oid->subs[i];

        while(tp && tp->subid != subid)
            tp = tp->next_peer;

        /* Did we find a match? */
        if(tp && i == oid->len - 1)
            break;
    }

    return tp;
}

void
rb_mib_uninit()
{
    if(initialized) {
        unload_all_mibs();
        rb_messagex(LOG_DEBUG, "unloaded all MIB files");
    }
    initialized = 0;
}
