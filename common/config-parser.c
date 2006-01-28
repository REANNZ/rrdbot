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
 */

#include "usuals.h"
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <dirent.h>

#include "config-parser.h"

static void
errmsg(const char* filename, void* data, const char* msg, ...)
{
    #define MAX_MSGLEN  1024
    char buf[MAX_MSGLEN];
    va_list ap;

    va_start(ap, msg);
    vsnprintf(buf, MAX_MSGLEN, msg, ap);
    buf[MAX_MSGLEN - 1] = 0;
    cfg_error(filename, buf, data);
    va_end(ap);
}

/* -----------------------------------------------------------------------------
 * CONFIG PARSER
 */

static char*
read_config_file(const char* configfile, void* data)
{
    char* config = NULL;
    FILE* f = NULL;
    long len;

    ASSERT(configfile);

    f = fopen(configfile, "r");
    if(f == NULL)
    {
        errmsg(configfile, data, "couldn't open config file: %s", configfile);
        return NULL;
    }

    /* Figure out size */
    if(fseek(f, 0, SEEK_END) == -1 || (len = ftell(f)) == -1 || fseek(f, 0, SEEK_SET) == -1)
    {
        errmsg(configfile, data, "couldn't seek config file: %s", configfile);
        return NULL;
    }

    if((config = (char*)malloc(len + 2)) == NULL)
    {
        errmsg(configfile, data, "out of memory");
        return NULL;
    }

    /* And read in one block */
    if(fread(config, 1, len, f) != len)
    {
        errmsg(configfile, data, "couldn't read config file: %s", configfile);
        return NULL;
    }

    fclose(f);

    /* Null terminate the data */
    config[len] = '\n';
    config[len + 1] = 0;

    /* Remove nasty dos line endings */
    strcln(config, '\r');

    return config;
}

int
cfg_parse_file(const char* filename, void* data, char** memory)
{
    char* name = NULL;
    char* value = NULL;
    char* config;
    char* next;
    char* header;
    int ret = -1;
    char* p;
    char* t;

    ASSERT(filename);

    config = read_config_file(filename, data);
    next = config;

    /* Go through lines and process them */
    while((t = strchr(next, '\n')) != NULL)
    {
        *t = 0;
        p = next; /* Do this before cleaning below */
        next = t + 1;

        t = strbtrim(p);

        /* Continuation line (had spaces at start) */
        if(p < t && *t)
        {
            if(!value)
            {
                errmsg(filename, data, "%s: invalid continuation in config: %s",
                       filename, p);
                goto finally;
            }

            /* Calculate the end of the current value */
            t = value + strlen(value);
            ASSERT(t < p);

            /* Continuations are separated by spaces */
            *t = ' ';
            t++;

            continue;
        }

        /* No continuation hand off value if necessary */
        if(name && value)
        {
            if(cfg_value(filename, header, name, value, data) == -1)
                goto finally;
        }

        name = NULL;
        value = NULL;

        /* Empty lines / comments at start / comments without continuation */
        if(!*t || *p == '#')
            continue;

        /* A header */
        if(*p == '[')
        {
            t = p + strcspn(p, "]");
            if(!*t || t == p + 1)
            {
                errmsg(filename, data, "%s: invalid config header: %s",
                       filename, p);
                goto finally;
            }

            *t = 0;
            header = strtrim(p + 1);
            continue;
        }

        /* Look for the break between name = value on the same line */
        t = p + strcspn(p, ":=");
        if(!*t)
        {
            errmsg(filename, data, "%s: invalid config line: %s",
                   filename, p);
            goto finally;
        }

        /* Null terminate and split value part */
        *t = 0;
        t++;

        name = strtrim(p);
        value = strtrim(t);
    }

    if(name && value)
    {
        if(cfg_value(filename, header, name, value, data) == -1)
            goto finally;
    }

    ret = 0;


finally:

    if(!memory || ret != 0)
        free(config);
    else if(memory)
        *memory = config;

    return ret;
}

int
cfg_parse_dir(const char* dirname, void* data)
{
    char olddir[MAXPATHLEN];
    struct dirent* dire;
    char *memory;
    DIR* dir;

    ASSERT(dirname != NULL);

    if(!getcwd(olddir, MAXPATHLEN))
        olddir[0] = 0;

    if(chdir(dirname) == -1)
        errmsg(NULL, data, "couldn't list config directory: %s", dirname);

    dir = opendir(".");
    if(!dir)
    {
        errmsg(NULL, data, "couldn't list config directory: %s", dirname);
        return -1;
    }

    while((dire = readdir(dir)) != NULL)
    {
        if(dire->d_type != DT_REG && dire->d_type != DT_LNK)
            continue;

        /* Build a happy path name */
        cfg_parse_file(dire->d_name, data, &memory);

        /* We call it with blanks after files */
        if(cfg_value(dire->d_name, NULL, NULL, NULL, data) == -1)
            break;

        /* Keep the memory around */
        if(memory)
            atexitv(free, memory);
    }

    closedir(dir);

    return 0;
}
