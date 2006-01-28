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
#include <syslog.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>

#include "rrdbotd.h"

/* Whether we print warnings when loading MIBs or not */
extern int g_mib_warnings;
extern const char* g_mib_directory;

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
            rb_mib_init(g_mib_directory, g_mib_warnings);

            /*
             * If we haven't parsed anything yet, try a symbolic
             * search for root
             */

            if(oid->len == 0)
            {
                n = rb_mib_lookup(src);
                if(n)
                {
                    /* That took care of it */
                    rb_mib_oid(n, oid);
                    continue;
                }
            }

            /* Try a by name search for sub item */
            n = rb_mib_node(oid);
            if(n == NULL)
                sub = -1;
            else
                sub = rb_mib_subid(n, src);
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
rb_snmp_parse_mib(const char* mib, struct snmp_value* value)
{
    int ret;
    mib_node n;

    value->syntax = SNMP_SYNTAX_NULL;
    memset(&(value->v), 0, sizeof(value->v));

    /* An initial dot */
    if(*mib == '.')
        mib++;

    /*
     * First try parsing a numeric OID. This will fall
     * back to mixed mode MIB's if necassary. Allows us
     * to avoid loading all the MIB files when not
     * necessary
     */

    ret = parse_mixed_mib(mib, &(value->var));

    /* Next try a symolic search */
    if(ret == -1)
    {
        rb_mib_init(g_mib_directory, g_mib_warnings);

        n = rb_mib_lookup(mib);
        if(n == NULL)
            return -1;

        rb_mib_oid(n, &(value->var));
        return 0;
    }

    return ret;
}
