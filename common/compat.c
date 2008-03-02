/*
 * Copyright (c) 2004, Stefan Walter
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

#include <sys/types.h>

#include <ctype.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <strings.h>

#include "usuals.h"
#include "compat.h"

#ifndef HAVE_STRCLN

void
strcln(char* data, char ch)
{
    char* p;
    for(p = data; *data; data++, p++)
    {
        while(*data == ch)
            data++;
        *p = *data;
    }

    /* Renull terminate */
    *p = 0;
}

#endif /* HAVE_STRCLN */

#ifndef HAVE_STRBTRIM

char*
strbtrim(const char* data)
{
    while(*data && isspace(*data))
        ++data;
    return (char*)data;
}

#endif /* HAVE_STRBTRIM */

#ifndef HAVE_STRETRIM

void
stretrim(char* data)
{
    char* t = data + strlen(data);
    while(t > data && isspace(*(t - 1)))
    {
        t--;
        *t = 0;
    }
}

#endif /* HAVE_STRETRIM */

#ifndef HAVE_STRTRIM

char*
strtrim(char* data)
{
    data = (char*)strbtrim(data);
    stretrim(data);
    return data;
}

#endif /* HAVE_STRTRIM */

#ifndef HAVE_STRTOB

int
strtob(const char* str)
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

#endif /* HAVE_STRTOB */


#ifndef HAVE_STRLCPY

size_t
strlcpy(char *dst, const char *src, size_t len)
{
        size_t ret = strlen(src);
        size_t copied;

        while (ret > 0 && len > 1) {
                *dst++ = *src++;
                --len;
                --ret;
                ++copied;
        }
        if (len > 0)
                *dst = '\0';
        return copied;
}

#endif /* HAVE_STRLCPY */

#ifndef HAVE_STRLCAT

size_t
strlcat(char* dst, const char* src, size_t siz)
{
    char* d = dst;
    const char* s = src;
    size_t n = siz;
    size_t dlen;

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

#endif /* HAVE_STRLCAT */

#ifndef HAVE_ATEXITV

typedef void (*voidfunc)(void*);
typedef struct _exit_stack
{
    voidfunc func;
    void* data;

    /* We have a list of these beauties */
    struct _exit_stack* next;
}
exit_stack;

/* Our exit stack */
static exit_stack* atexits = NULL;
static int atexit_registered = 0;

static void
atexit_do_stack(void)
{
    exit_stack* next;
    for(; atexits; atexits = next)
    {
        next = atexits->next;
        (atexits->func)(atexits->data);
        free(atexits);
    }
}

void
atexitv(voidfunc func, void* data)
{
    exit_stack* ae;

    ASSERT(func);

    ae = (exit_stack*)calloc(1, sizeof(exit_stack));
    if(ae)
    {
        ae->func = func;
        ae->data = data;
        ae->next = atexits;
        atexits = ae;

        if(!atexit_registered)
            atexit(atexit_do_stack);
    }
}

#endif /* HAVE_ATEXITV */


#ifndef HAVE_XCALLOC

void*
xcalloc(size_t size)
{
    register void* value = calloc(1, size);
    if(value == NULL)
        errx(1, "out of memory");
    return value;
}

#endif /* HAVE_XCALLOC */


#ifndef HAVE_STRLWR

void strlwr(char* data)
{
    while(*data)
    {
        *data = tolower(*data);
        data++;
    }
}

#endif /* HAVE_STRLWR */


#ifndef HAVE_STRUPR

void strupr(char* data)
{
    while(*data)
    {
        *data = toupper(*data);
        data++;
    }
}

#endif /* HAVE_STRUPR */
