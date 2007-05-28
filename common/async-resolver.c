/*
 * Copyright (c) 2006, Stefan Walter
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
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include "async-resolver.h"
#include "server-mainloop.h"

/* -----------------------------------------------------------------------------
 * THREAD COMMUNICATION
 */

#define TSIGNAL_UNITITIALIZED  { -1, -1 }

static int
tsignal_init(int* sig)
{
    if(pipe(sig) == -1)
        return -1;
    fcntl(sig[0], F_SETFL, fcntl(sig[0], F_GETFL, 0) | O_NONBLOCK);
    return 0;
}

static int
tsignal_get_fd(int* sig)
{
    return sig[0];
}

static void
tsignal_wake(int* sig)
{
    write(sig[1], "1", 1);
}

static void
tsignal_clear(int* sig)
{
    char buf[16];
    while(read(sig[0], buf, sizeof(buf)) > 0);
}

static void
tsignal_wait(int* sig, struct timeval* tv)
{
    fd_set watch;
    FD_ZERO(&watch);
    FD_SET(sig[0], &watch);
    select(sig[0], &watch, NULL, NULL, tv);
}

static void
tsignal_uninit(int* sig)
{
    if(sig[1] != -1)
        close(sig[1]);
    sig[1] = -1;
    if(sig[0] != -1)
        close(sig[0]);
    sig[0] = -1;
}

/* -----------------------------------------------------------------------------
 * RESOLVER
 */

typedef struct _resolve_request
{
    char hostname[256];
    char servname[256];
    struct addrinfo hints;
    async_resolve_callback cb;
    void *arg;

    int gaierr;
    int errn;
    struct addrinfo *ai;

    struct _resolve_request *next;
}
resolve_request;

/* The queues */
static int res_quit = 0;
static resolve_request* res_requests = NULL;
static resolve_request* res_done = NULL;

/* Thread communication */
static pthread_t res_thread = 0;
static pthread_mutex_t res_mutex = PTHREAD_MUTEX_INITIALIZER;
static int res_request_signal[2] = TSIGNAL_UNITITIALIZED;
static int res_done_signal[2] = TSIGNAL_UNITITIALIZED;

static void*
resolver_thread(void* arg)
{
    resolve_request* req;
    resolve_request* r;
    struct timeval tv;

    while(!res_quit)
    {
        pthread_mutex_lock(&res_mutex);

            /* Dig out any requests */
            req = res_requests;
            if(req)
            {
                res_requests = req->next;
                req->next = NULL;
            }

        pthread_mutex_unlock(&res_mutex);

        /* No requests, wait for a request */
        if(!req)
        {
            tv.tv_sec = 0;
            tv.tv_usec = 500000;
            tsignal_wait(res_request_signal, &tv);
            tsignal_clear(res_request_signal);
            continue;
        }

        /* The actual resolve */
        req->gaierr = getaddrinfo(req->hostname, req->servname[0] ? req->servname : NULL,
                                  &req->hints, &req->ai);
        req->errn = errno;

        /* A timeout */
        if(!req->gaierr && !req->ai)
        {
            req->gaierr = EAI_SYSTEM;
            req->errn = ETIMEDOUT;
        }

        /* Append the result to done */
        pthread_mutex_lock(&res_mutex);

            if(!res_done)
            {
                res_done = req;
            }
            else
            {
                r = res_done;
                while(r->next)
                    r = r->next;
                r->next = req;
            }

        pthread_mutex_unlock(&res_mutex);

        /* Tell the main thread to check outbound */
        tsignal_wake(res_done_signal);
    }

    return NULL;
}

static void
resolver_done(int fd, int type, void* arg)
{
    resolve_request* req;
    resolve_request* r;

    tsignal_clear(res_done_signal);

    pthread_mutex_lock(&res_mutex);

        req = res_done;
        res_done = NULL;

    pthread_mutex_unlock(&res_mutex);

    while(req)
    {
        /* Send off the result */
        errno = req->errn;
        (req->cb)(req->gaierr, req->ai, req->arg);

        /* And free it all */
        r = req->next;
        if(req->ai)
            freeaddrinfo(req->ai);
        free(req);

        req = r;
    }
}

int
async_resolver_init()
{
    int r;

    /* The signal pipes */
    if(tsignal_init(res_request_signal) < 0)
        return -1;
    if(tsignal_init(res_done_signal) < 0)
        return -1;

    if(server_watch(tsignal_get_fd(res_done_signal), SERVER_READ, resolver_done, NULL) == -1)
        return -1;

    r = pthread_create(&res_thread, NULL, resolver_thread, NULL);
    if(r != 0)
    {
        res_thread = 0;
        return -1;
    }

    return 0;
}

void
async_resolver_queue(const char* hostname, const char* servname,
                     struct addrinfo* hints, async_resolve_callback cb, void* arg)
{
    resolve_request* req;
    resolve_request* r;
    char* t;

    if(!res_thread)
    {
        /* All errors go to callback */
        errno = ESRCH;
        (cb)(EAI_SYSTEM, NULL, arg);
        return;
    }

    req = calloc(1, sizeof(resolve_request));
    if(!req)
    {
        /* All errors go to callback */
        (cb)(EAI_MEMORY, NULL, arg);
        return;
    }

    req->cb = cb;
    req->arg = arg;

    strncpy(req->hostname, hostname, sizeof(req->hostname));
    req->hostname[sizeof(req->hostname) - 1] = 0;

    /* A colon and we try to split */
    t = strchr(req->hostname, ':');
    if(t)
    {
        *t = 0;
        strncpy(req->servname, t + 1, sizeof(req->servname));
    }

    if(servname && !req->servname[0])
        strncpy(req->servname, servname, sizeof(req->servname));
    req->servname[sizeof(req->servname) - 1] = 0;

    if(hints)
        memcpy(&(req->hints), hints, sizeof(req->hints));

    /* Append the result to requests */
    pthread_mutex_lock(&res_mutex);

        if(!res_requests)
        {
            res_requests = req;
        }
        else
        {
            r = res_requests;
            while(r->next)
                r = r->next;
            r->next = req;
        }

    pthread_mutex_unlock(&res_mutex);

    tsignal_wake(res_request_signal);
}

void
async_resolver_uninit()
{
    resolve_request* req;

    /* No more responses from this point on */
    if(tsignal_get_fd(res_done_signal) != -1)
        server_unwatch(tsignal_get_fd(res_done_signal));

    pthread_mutex_lock(&res_mutex);

        while(res_requests)
        {
            req = res_requests->next;
            if(res_requests->ai)
                freeaddrinfo(res_requests->ai);
            free(res_requests);
            res_requests = req;
        }

        while(res_done)
        {
            req = res_done->next;
            if(res_done->ai)
                freeaddrinfo(res_done->ai);
            free(res_done);
            res_done = req;
        }

    pthread_mutex_unlock(&res_mutex);

    /* Wake up the resolver thread */
    res_quit = 1;
    tsignal_uninit(res_request_signal);

    /* Wait for it to finish */
    if(res_thread)
    {
        pthread_join(res_thread, NULL);
        res_thread = 0;
    }

    /* And close up the signals in the other direction */
    tsignal_uninit(res_done_signal);
}
