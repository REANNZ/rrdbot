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

#define _GNU_SOURCE

#include "usuals.h"
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include "stringx.h"
#include "rrdbotd.h"

#define MAX_NUMLEN 40

void rb_rrd_update(rb_poller *poll)
{
    char buf[MAX_NUMLEN];
    const char* argv[5];
    char* template;
    char* items;
    int r, tlen, ilen;
    rb_item *it;

    if(!poll->items)
        return;

    tlen = 0;
    ilen = 3;

    for(it = poll->items; it; it = it->next)
    {
        tlen += strlen(it->rrdfield) + 1;
        ilen += 40;
    }

    template = (char*)calloc(tlen, sizeof(char));
    items = (char*)calloc(ilen, sizeof(char));

    if(!template || !items)
    {
        if(items)
            free(items);
        if(template)
            free(template);
        rb_messagex(LOG_CRIT, "out of memory");
        return;
    }

    /* Put in the right time */
    snprintf(items, ilen, "%lld:", (poll->last_polled / 1000L));

    /* Build the rest of the arguments */
    for(it = poll->items; it; it = it->next)
    {
        if(it != poll->items)
        {
            strlcat(template, ":", tlen);
            strlcat(items, ":", ilen);
        }

        strlcat(template, it->rrdfield, tlen);

        if(it->value == RB_UNKNOWN)
            strlcat(items, "U", ilen);
        else
        {
            snprintf(buf, MAX_NUMLEN, "%.4lf", it->value);
            buf[MAX_NUMLEN - 1] = 0;
            strlcat(items, buf, ilen);
        }
    }

    /* Always have to clear before calling rrdtool. klunky :( */
    optind = 0;
    opterr = 0;

    /* TODO: We need support for @ to specify when these values occurred */

    argv[0] = "rrdupdate";
    argv[1] = poll->rrdname;
    argv[2] = "-t";
    argv[3] = template;
    argv[4] = items;

    rb_messagex(LOG_DEBUG, "updating RRD file: %s", poll->rrdname);
    rb_messagex(LOG_DEBUG, "> template: %s", template);
    rb_messagex(LOG_DEBUG, "> values: %s", items);

    rrd_clear_error();
    r = rrd_update(5, argv);

    if(r != 0)
        rb_messagex(LOG_ERR, "couldn't update rrd file: %s: %s",
                    poll->rrdname, rrd_get_error());

    free(template);
    free(items);
}
