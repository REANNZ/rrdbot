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

#include <fcntl.h>
#include <stdio.h>
#include <time.h>

#include "usuals.h"
#include "log.h"
#include "rrdbotd.h"

#define MAX_NUMLEN 40
#define RAW_BUFLEN 768

static void write_sample(int, const time_t*, const rb_item*, const char*);

void rb_rrd_update(rb_poller *poll)
{
    rb_item *item;
    file_path *rawpath;

    if(!poll->items)
        return;

    /* Loop through all the attached raw files */
    for(rawpath = poll->rawlist; rawpath; rawpath = rawpath->next) {
        for(item = poll->items; item; item = item->next) {
            char path[MAXPATHLEN];
            int fd;
            struct tm *timeinfo;
            time_t time;
            size_t len;

            /* time expects seconds */
            time = item->last_polled / 1000L;
            timeinfo = localtime(&time);
            len = strftime(path, sizeof(path), rawpath->path, timeinfo);

            if(len == 0)
            {
                log_errorx("raw file: %s: strftime: %s", rawpath->path, strerror(errno));
                break; /* next raw file */
            }

            log_debug ("updating RAW file: %s -> %s", rawpath->path, path);

            if((fd = open(path, O_WRONLY|O_APPEND|O_CREAT, 0644)) == -1)
            {
                log_errorx("raw file: %s: open: %s", path, strerror(errno));
                break; /* next raw file */
            }

            write_sample(fd, &time, item, path /* for logging */);

            if (close(fd) == -1)
            {
                log_errorx("raw file: %s: close: %s", path, strerror(errno));
            }
        }
    }
}

static void
write_sample(int fd, const time_t *time, const rb_item *item, const char* fd_path)
{
    char buf[RAW_BUFLEN];
    ssize_t nw;
    int n;

    switch (item->vtype) {
    case VALUE_REAL:
        n = snprintf(buf, sizeof(buf), "%"PRId64"\t%s\t%"PRId64"\n",
          *time,
          (item->reference ? item->reference : item->field),
          item->v.i_value);
        break;

    case VALUE_FLOAT:
        n = snprintf(buf, sizeof(buf), "%"PRId64"\t%s\t%.4lf\n",
          *time,
          (item->reference ? item->reference : item->field),
          item->v.f_value);
        break;

    case VALUE_UNSET:
        n = snprintf(buf, sizeof(buf), "%"PRId64"\t%s\t\n",
          *time,
          (item->reference ? item->reference : item->field));
        break;

    default:
        log_errorx("raw file: %s: unknown sample value type: %d", fd_path, item->vtype);
        return;
    }

    if (n == -1) {
        log_errorx("raw file: %s: snprintf: %s", fd_path, strerror(errno));
        return;
    }

    if (n >= sizeof(buf)) {
        log_errorx("raw file: %s: truncated sample string: required: %d", fd_path, n);
        return;
    }

    if ((nw = write(fd, buf, n)) == -1) {
        log_errorx("raw file: %s: write: %s", fd_path, strerror(errno));
        return;
    }

    if (nw != n) {
        log_errorx("raw file: %s: partial write: %d of %d", fd_path, nw, n);
        return;
    }
}
