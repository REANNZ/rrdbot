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
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>

#include <rrd.h>

#include "log.h"
#include "rrdbotd.h"

#define MAX_NUMLEN 40

char* get_parent(const char *path)
{
    char *copy = NULL;
    char *parent = NULL;
    char *ret = NULL;

    if((copy = strdup(path)) == NULL)
    {
        log_errorx ("out of memory");
        goto finally;
    }

    if((parent = dirname(copy)) == NULL)
        goto finally;
    
    if(parent == copy)
    {
        ret = parent;
        copy = NULL;
    }
    else
    {
        if((ret = strdup(parent)) == NULL)
        {
            log_errorx ("out of memory");
            goto finally;
        }
    }

finally:
    if(copy)
        free(copy);

    return ret;
}

/* Function with behaviour like `mkdir -p'  */
int mkdir_p(const char *path, mode_t mode)
{
    int ret = -1;
    char *parent = NULL;

    if((parent = get_parent(path)) == NULL)
        goto finally;

    /* Check whether we've reached the root */
    if(strcmp(parent, path) == 0)
    {
        ret = 0;
        goto finally;
    }

    if((mkdir_p(parent, mode) == -1) && (errno != EEXIST))
        goto finally;

    log_debug ("creating directory: %s", path);
    if((mkdir(path, mode) == -1) && (errno != EEXIST))
        goto finally;
    
    ret = 0;

finally:
    if(parent)
        free(parent);

    return ret;
}

void rb_rrd_update(rb_poller *poll)
{
    char buf[MAX_NUMLEN];
    const char* argv[5];
    char* template;
    char* items;
    int r, tlen, ilen;
    rb_item *item;
    file_path *rrdpath;
    file_path *rawpath;

    if(!poll->items)
        return;

    tlen = 0;
    ilen = MAX_NUMLEN + 1; /* Timestamp ':' */

    for(item = poll->items; item; item = item->next)
    {
        tlen += strlen(item->field) + 1; /* Field plus ':' or '\0' */
        ilen += MAX_NUMLEN + 1;          /* Value plus ':' or '\0' */
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
    snprintf(items, ilen, "%" PRId64 ":", (poll->last_polled / 1000L));

    /* Build the rest of the arguments */
    for(item = poll->items; item; item = item->next)
    {
        if(item != poll->items)
        {
            strlcat(template, ":", tlen);
            strlcat(items, ":", ilen);
        }

        strlcat(template, item->field, tlen);

        if(item->vtype == VALUE_UNSET)
            strlcat(items, "U", ilen);
        else
        {
            if(item->vtype == VALUE_FLOAT)
                snprintf(buf, MAX_NUMLEN, "%.4lf", item->v.f_value);
            else
                snprintf(buf, MAX_NUMLEN, "%" PRId64, item->v.i_value);
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

    free(template);
    free(items);

    /* Loop through all the attached raw files */
    for(rawpath = poll->rawlist; rawpath; rawpath = rawpath->next) {
        for(item = poll->items; item; item = item->next) {
            char path[MAXPATHLEN];
            char *parent = NULL;
            FILE *fp;
            struct tm *timeinfo;
            time_t time;
            size_t len;

            /* time expects seconds */
            time = item->last_polled / 1000L;
            timeinfo = localtime(&time);
            len = strftime(path, sizeof(path), rawpath->path, timeinfo);

            if(len == 0)
            {
                log_errorx("couldn't strftime the raw file path: %s for writting : %s",
                            rawpath->path, strerror(errno));
                /* Try the next raw file */
                continue;
            }

            log_debug ("updating RAW file: %s -> %s", rawpath->path, path);

            /* try to ensure directory exists */
            if((parent = get_parent(path)) == NULL)
                return;
            if((mkdir_p(parent, 0777) == -1) && (errno != EEXIST))
            {
                log_errorx("couldn't create directory for raw file: %s : %s",
                            path,  strerror(errno));
                free(parent);
                /* Try the next item */
                continue;
            }
            free(parent);
        
            fp = fopen(path, "a");
            if(fp == NULL)
            {
                log_errorx("couldn't open raw file: %s for writing : %s",
                            path,  strerror(errno));
                /* Try the next item */
                continue;
            }

            /* Write item record to raw file */
            fprintf(fp, "%" PRId64 "\t", time);
            if(item->reference)
                fprintf(fp, "%s", item->reference);
            else
                fprintf(fp, "%s", item->field);
            fprintf(fp, "\t");
            if(item->vtype == VALUE_REAL)
                fprintf(fp, "%" PRId64, item->v.i_value);
            else if(item->vtype == VALUE_FLOAT)
                fprintf(fp, "%.4lf", item->v.f_value);
            fprintf(fp, "\n");

            fclose(fp);
        }
    }
}
