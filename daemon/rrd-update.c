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

#define _GNU_SOURCE

#include "usuals.h"
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <rrd.h>

#include "log.h"
#include "rrdbotd.h"

#define MAX_NUMLEN 40

void rb_rrd_update(rb_poller *poll)
{
    char buf[MAX_NUMLEN];
    const char* argv[5];
    char* template;
    char* items;
    char* c;
    int r, tlen, ilen;
    rb_item *it;
    file_path *rrdpath;
    file_path *rawpath;

    if(!poll->items)
        return;

    tlen = 0;
    ilen = 3;

    for(it = poll->items; it; it = it->next)
    {
        tlen += strlen(it->field) + 1;
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
        log_errorx ("out of memory");
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

        strlcat(template, it->field, tlen);

        if(it->vtype == VALUE_UNSET)
            strlcat(items, "U", ilen);
        else
        {
            if(it->vtype == VALUE_FLOAT)
                snprintf(buf, MAX_NUMLEN, "%.4lf", it->v.f_value);
            else
                snprintf(buf, MAX_NUMLEN, "%lld", it->v.i_value);
            buf[MAX_NUMLEN - 1] = 0;
            strlcat(items, buf, ilen);
        }
    }

    /* Loop through all the attached rrd files */
    for(rrdpath = poll->rrdlist; rrdpath; rrdpath = rrdpath->next)
    {
        /* Always have to clear before calling rrdtool. klunky :( */
        optind = 0;
        opterr = 0;

        argv[0] = "rrdupdate";
        argv[1] = rrdpath->path;
        argv[2] = "-t";
        argv[3] = template;
        argv[4] = items;

        log_debug ("updating RRD file: %s", rrdpath->path);
        log_debug ("> template: %s", template);
        log_debug ("> values: %s", items);

        rrd_clear_error();
        r = rrd_update(5, (char**)argv);

        if(r != 0)
            log_errorx ("couldn't update rrd file: %s: %s",
                        rrdpath->path, rrd_get_error());
    }

    /* Replace our :'s with ',' using csv format for raw files */
    for(c = items; *c; c++)
    {
        if(*c == ':') 
            *c = ',';
    }

    /* Loop through all the attached raw files */
    for(rawpath = poll->rawlist; rawpath; rawpath = rawpath->next)
    {
        char path[MAXPATHLEN];
        FILE *fp;
        struct tm *timeinfo;
        time_t time;
        size_t len;

        /* time expects seconds */
        time = poll->last_polled / 1000;
        timeinfo = localtime(&time);
        len = strftime(path, sizeof(path), rawpath->path, timeinfo);

        if(len == 0)
        {
            log_errorx("couldn't strftime the raw file path: %s for writting : %s",
                        rawpath->path, rrd_get_error());
            /* Try the next raw file */
            continue;
        }

        log_debug ("updating RAW file: %s -> %s", rawpath->path, path);

        if(access(path, R_OK | W_OK) != -1)
        {
            /* File exists */
            fp = fopen(path, "a");

            if(fp == NULL)
            {
                log_errorx("couldn't open raw file: %s for writing : %s",
                            path, rrd_get_error());
                /* Try the next raw file */
                continue;
            }
        } else {
            /* Creating new file */
            fp = fopen(path, "w");

            if(fp == NULL)
            {
                log_errorx("couldn't open raw file: %s for writing : %s",
                            path, rrd_get_error());
                /* Try the next raw file */
                continue;
            }

            /* Put header names into the file */
            fprintf(fp, "ts,");
            
            for(it = poll->items; it; it = it->next)
            {
                if (it->next)
                    fprintf(fp, "%s,", it->field);
                else
                    fprintf(fp, "%s\n", it->field);
            }
        }

        if(fprintf(fp, "%s\n", items) == 0)
            log_errorx("failed to write to raw file: %s : %s",
                        path, rrd_get_error());

        fclose(fp);
    }

    free(template);
    free(items);
}
