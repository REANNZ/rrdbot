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
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <syslog.h>
#include <stdarg.h>
#include <err.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>

#include "parse.h"
#include "mib-parser.h"

/* Whether we print warnings when loading MIBs or not */
const char* mib_directory = DEFAULT_MIB;
int mib_warnings = 0;
static int initialized = 0;

/* -----------------------------------------------------------------------------
 * DEFINITIONS
 */

#define FALSE 0
#define TRUE 1

/* No need to implement these */
#define DEBUGMSGTL(x)
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
        return mib_warnings;
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

static void
snmp_log(int level, const char* msg, ...)
{
    va_list ap;

    if(level >= LOG_WARNING && !mib_warnings)
        return;

    va_start(ap, msg);
    vwarnx(msg, ap);
    va_end(ap);
}

/* Only used to open files */
static void
snmp_log_perror(const char* file)
{
    warn("couldn't open file: %s", file);
}

#define SNMP_FREE(s)           do { if (s) { free((void *)s); s=NULL; } } while(0)

/* -----------------------------------------------------------------------------
 * PRIVATE DECLARATIONS
 */

typedef void* mib_node;

mib_node mib_lookup(const char* match);
int mib_subid(mib_node n, const char* name);
void mib_oid(mib_node n, struct asn_oid* oid);
mib_node mib_get_node(struct asn_oid* oid);

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
mib_init()
{
    if(initialized)
        return;

    init_mib_internals();
    add_mibdir(mib_directory);
    read_all_mibs();

    initialized = 1;
}

mib_node
mib_lookup(const char* match)
{
    extern struct tree *tree_head;
    struct tree* mib;

    ASSERT(initialized);

    clear_tree_flags(tree_head);
    mib = find_best_tree_node(match, NULL, NULL);
    return (mib_node)mib;
}

int
mib_subid(mib_node n, const char* name)
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
mib_oid(mib_node n, struct asn_oid* oid)
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
mib_get_node(struct asn_oid* oid)
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
mib_uninit()
{
    if(initialized)
        unload_all_mibs();
    initialized = 0;
}

/* -----------------------------------------------------------------------------
 * INCLUDE parse.c
 */

#include "parse.c"

/* -------------------------------------------------------------------------- */

static int
parse_mixed_mib(const char* mib, struct asn_oid* oid)
{
    mib_node n;
    int ret = 0;
    unsigned int sub;
    char* next;
    char* t;
    char* copy;
    char* src;

    memset(oid, 0, sizeof(*oid));

    copy = strdup(mib);
    if(!copy)
    {
        errno = ENOMEM;
        return -1;
    }

    for(src = copy; src && *src; src = next)
    {
        next = strchr(src, '.');
        if(next)
        {
            *next = 0;
            next++;
        }

        sub = strtoul(src, &t, 10);

        /* An invalid number, try getting a named MIB */
        if(*t || sub < 0)
        {
            /* Only initializes first time around */
            mib_init();

            /*
             * If we haven't parsed anything yet, try a symbolic
             * search for root
             */

            if(oid->len == 0)
            {
                n = mib_lookup(src);
                if(n)
                {
                    /* That took care of it */
                    mib_oid(n, oid);
                    continue;
                }
            }

            /* Try a by name search for sub item */
            n = mib_get_node(oid);
            if(n == NULL)
                sub = -1;
            else
                sub = mib_subid(n, src);
        }

        /* Make sure this is a valid part */
        if(sub < 0 || (oid->len == 0 && sub < 1) || sub >= ASN_MAXID)
            ret = -1;

        /* Too many parts */
        if(oid->len > ASN_MAXOIDLEN)
            ret = -1;

        if(ret < 0)
            break;

        oid->subs[oid->len] = sub;
        oid->len++;
    }

    free(copy);
    return ret;
}

int
mib_parse(const char* mib, struct asn_oid* oid)
{
    int ret;
    mib_node n;

    /* An initial dot */
    if(*mib == '.')
        mib++;

    /*
     * First try parsing a numeric OID. This will fall
     * back to mixed mode MIB's if necassary. Allows us
     * to avoid loading all the MIB files when not
     * necessary
     */

    ret = parse_mixed_mib(mib, oid);

    /* Next try a symolic search */
    if(ret == -1)
    {
        mib_init();

        n = mib_lookup(mib);
        if(n == NULL)
            return -1;

        mib_oid(n, oid);
        return 0;
    }

    return ret;
}

int
mib_format(struct asn_oid* oid, FILE* f)
{
    extern struct tree *tree_head;
    struct tree *tp = NULL;
    asn_subid_t subid;
    int i;

    mib_init();

    for(i = 0, tp = tree_head; tp && i < oid->len;
        i++, tp = tp ? tp->child_list : NULL)
    {
        subid = oid->subs[i];

        while(tp && tp->subid != subid)
            tp = tp->next_peer;

        if(!tp)
            break;

        fprintf(f, ".%s", tp->label);
    }

    for( ; i < oid->len; i++)
        fprintf(f, ".%d", (int)(oid->subs[i]));

    return 0;
}
