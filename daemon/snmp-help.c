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

#include "stringx.h"
#include "rrdbotd.h"

static int
parse_numeric_mib(const char* mib, struct asn_oid* oid)
{
    int ret = 0;
    unsigned int sub;
    char* next;
    char* t;
    char* copy;
    char* src;

    memset(oid, 0, sizeof(*oid));

    copy = src = strdup(mib);
    if(!src)
        return -1;

    while(src && *src)
    {
        next = strchr(src, '.');
        if(next)
            *next = 0;

        sub = strtoul(src, &t, 10);

        /* Too many parts */
        if(oid->len > ASN_MAXOIDLEN)
            ret = -1;

        /* An invalid number */
        if(*t)
            ret = -1;

        /* Make sure this is a valid part */
        if((oid->len == 0 && sub < 1) || sub < 0 || sub >= ASN_MAXID)
            ret -1;

        if(ret < 0)
            break;

        oid->subs[oid->len] = sub;
        oid->len++;

        src = next ? next + 1 : NULL;
    }

    free(copy);
    return ret;
}

int
rb_parse_mib(const char* mib, struct snmp_value* value)
{
    /*
     * TODO: Eventually we'll have code here to parse symbolic
     * names, and initialize snmp_value to the right type and
     * all that jazz. For now we just have numeric OID support.
     */

    value->syntax = SNMP_SYNTAX_NULL;
    memset(&(value->v), 0, sizeof(value->v));

    return parse_numeric_mib(mib, &(value->var));
}
