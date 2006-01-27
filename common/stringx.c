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

#include <sys/types.h>

#include <ctype.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "usuals.h"
#include "stringx.h"

void
remove_cr(char* data)
{
    char* p;
    for(p = data; *data; data++, p++)
    {
        while(*data == '\r')
            data++;
        *p = *data;
    }

    /* Renull terminate */
    *p = 0;
}

char*
trim_start(const char* data)
{
    while(*data && isspace(*data))
        ++data;
    return (char*)data;
}

void
trim_end(char* data)
{
    char* t = data + strlen(data);
    while(t > data && isspace(*(t - 1)))
    {
        t--;
        *t = 0;
    }
}

char*
trim_space(char* data)
{
    data = (char*)trim_start(data);
    trim_end(data);
    return data;
}

/* String to bool helper function */
int strtob(const char* str)
{
    if(strcasecmp(str, "0") == 0 ||
       strcasecmp(str, "no") == 0 ||
       strcasecmp(str, "false") == 0 ||
       strcasecmp(str, "f") == 0 ||
       strcasecmp(str, "off") == 0)
        return 0;

    if(strcasecmp(str, "1") == 0 ||
       strcasecmp(str, "yes") == 0 ||
       strcasecmp(str, "true") == 0 ||
       strcasecmp(str, "t") == 0 ||
       strcasecmp(str, "on") == 0)
        return 1;

    return -1;
}

size_t
strlcpy(char *dst, const char *src, size_t len)
{
        size_t ret = strlen(dst);

        while (len > 1) {
                *dst++ = *src++;
                len--;
        }
        if (len > 0)
                *dst = '\0';
        return (ret);
}

size_t strlcat(char* dst, const char* src, size_t siz)
{
    char* d = dst;
    const char* s = src;
    size_t n = siz;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end */
    while(n-- != 0 && *d != '\0')
     	d++;
    dlen = d - dst;
    n = siz - dlen;

    if(n == 0)
        return dlen + strlen(s);
    while(*s != '\0')
    {
        if(n != 1)
        {
            *d++ = *s;
            n--;
        }

        s++;
    }

    *d = '\0';

    return dlen + (s - src);       /* count does not include NUL */
}
