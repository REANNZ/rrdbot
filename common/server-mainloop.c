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

#include "usuals.h"
#include <errno.h>
#include <sys/time.h>
#include <err.h>

#include "server-mainloop.h"

#define timeval_to_ms(tv) \
    ((((uint64_t)(tv).tv_sec) * 1000L) + (((uint64_t)(tv).tv_usec) / 1000L))

typedef struct _socket_callback
{
    int fd;
    server_socket_callback callback;
    void* arg;

    struct _socket_callback* next;
}
socket_callback;

typedef struct _timer_callback
{
    struct timeval at;
    struct timeval interval;
    server_timer_callback callback;
    void* arg;

    struct _timer_callback* next;
}
timer_callback;

typedef struct _server_context
{
    int stopped;
    fd_set read_fds;
    fd_set write_fds;
    int max_fd;
    socket_callback* callbacks;
    timer_callback* timers;
}
server_context;

/* Global context */
static server_context ctx;

static int
add_timer(struct timeval at, int period_ms, server_timer_callback callback, void* arg)
{
    struct timeval interval;
    timer_callback* cb;

    ASSERT (period_ms);
    ASSERT(callback != NULL);

    interval.tv_sec = period_ms / 1000;
    interval.tv_usec = (period_ms % 1000) * 1000; /* into micro seconds */

    cb = (timer_callback*)calloc(1, sizeof(*cb));
    if(!cb)
    {
        errno = ENOMEM;
        return -1;
    }

    memcpy(&cb->at, &at, sizeof(cb->at));
    memcpy(&cb->interval, &interval, sizeof(cb->interval));

    cb->callback = callback;
    cb->arg = arg;

    cb->next = ctx.timers;
    ctx.timers = cb;

    return 0;
}

static timer_callback*
remove_timer(timer_callback* timcb)
{
    timer_callback* cb;
    timer_callback* next;

    if(!ctx.timers)
        return NULL;

    /* First in list */;
    if(ctx.timers == timcb)
    {
        cb = ctx.timers;
        ctx.timers = ctx.timers->next;
        free(cb);
        return ctx.timers;
    }

    /* One ahead processing of rest */
    for(cb = ctx.timers; cb->next; cb = cb->next)
    {
        if(cb->next == timcb)
        {
            next = cb->next->next;
            free(cb->next);
            cb->next = next;
            return cb->next;
        }
    }

    /* Couldn't remove, return self */
    return timcb;
}

void
server_init()
{
    memset(&ctx, 0, sizeof (ctx));
    FD_ZERO(&ctx.read_fds);
    FD_ZERO(&ctx.write_fds);

    ctx.max_fd = -1;
    ctx.stopped = 1;
    ctx.callbacks = NULL;
    ctx.timers = NULL;
}

void
server_uninit()
{
    timer_callback* timcb;
    timer_callback* timn;
    socket_callback* sockcb;
    socket_callback* sockn;

    for(timcb = ctx.timers; timcb; timcb = timn)
    {
        timn = timcb->next;
        free(timcb);
    }

    ctx.timers = NULL;

    for(sockcb = ctx.callbacks; sockcb; sockcb = sockn)
    {
        sockn = sockcb->next;
        free(sockcb);
    }

    ctx.callbacks = NULL;
}

uint64_t
server_get_time()
{
    struct timeval tv;
    if(gettimeofday(&tv, NULL) == -1)
        return 0L;
    return timeval_to_ms(tv);
}

int
server_run()
{
    struct timeval* timeout;
    struct timeval tv, current;
    timer_callback* timcb;
    socket_callback* sockcb;
    fd_set rfds, wfds;
    int r;

    /* No watches have been set */
    ASSERT(ctx.max_fd > -1);

    ctx.stopped = 0;

    while(!ctx.stopped)
    {
        /* Watch for the various fds */
        memcpy(&rfds, &ctx.read_fds, sizeof(rfds));
        memcpy(&wfds, &ctx.write_fds, sizeof(wfds));

        /* Prepare for timers */
        timeout = NULL;
        if(gettimeofday(&current, NULL) == -1)
            return -1;

        /* Cycle through timers */
        for(timcb = ctx.timers; timcb; )
        {
            ASSERT(timcb->callback);

            /* Call any timers that have already passed */
            if(timercmp(&current, &timcb->at, >=))
            {
                /* Convert to milliseconds, and make the call */
                r = (timcb->callback)(timeval_to_ms(current), timcb->arg);

                /* Reset timer if so desired */
                if (r == 1 && timerisset(&timcb->interval))
                {
                    timeradd(&timcb->at, &timcb->interval, &timcb->at);

                    /* If the new timeout has already passed, reset it to current time */
                    if(timercmp(&(timcb->at), &current, <=))
                        memcpy(&(timcb->at), &current, sizeof(timcb->at));
                }

                /* Otherwise remove it. Either one shot, or returned 0 */
                else
                {
                    timcb = remove_timer(timcb);
                    continue;
                }
            }

            /* Get soonest timer */
            if (!timeout || timercmp(&timcb->at, timeout, <))
                timeout = &timcb->at;

            timcb = timcb->next;
        }

        /* Convert to an offset */
        if(timeout)
        {
            memcpy(&tv, timeout, sizeof(tv));
            timeout = &tv;
            timersub(timeout, &current, timeout);
        }

        r = select(ctx.max_fd, &rfds, &wfds, NULL, timeout);
        if (r < 0)
        {
            /* Interrupted so try again, and possibly exit */
            if (errno == EINTR)
                continue;

            /* Programmer errors */
            ASSERT (errno != EBADF);
            ASSERT (errno != EINVAL);
            return r;
        }

        /* Timeout, just jump to timeout processing */
        if(r == 0)
            continue;

        for(sockcb = ctx.callbacks; sockcb; sockcb = sockcb->next)
        {
            ASSERT(sockcb->fd != -1);

            /* Call any that are set */
            if (FD_ISSET(sockcb->fd, &rfds))
                (sockcb->callback)(sockcb->fd, SERVER_READ, sockcb->arg);
            if (FD_ISSET(sockcb->fd, &wfds))
                (sockcb->callback)(sockcb->fd, SERVER_WRITE, sockcb->arg);
        }
    }

    return 0;
}

void
server_stop()
{
    ctx.stopped = 1;
}

int
server_stopped()
{
    return ctx.stopped;
}

int
server_watch(int fd, int type, server_socket_callback callback, void* arg)
{
    socket_callback* cb;
    ASSERT(type != 0);
    ASSERT(fd != -1);
    ASSERT(callback != NULL);

    cb = (socket_callback*)calloc(sizeof(*cb), 1);
    if(!cb)
    {
        errno = ENOMEM;
        return -1;
    }

    cb->fd = fd;
    cb->callback = callback;
    cb->arg = arg;

    cb->next = ctx.callbacks;
    ctx.callbacks = cb;

    if (type & SERVER_READ)
        FD_SET(fd, &ctx.read_fds);
    if (type & SERVER_WRITE)
        FD_SET(fd, &ctx.write_fds);

    if(fd >= ctx.max_fd)
        ctx.max_fd = fd + 1;

    return 0;
}

void
server_unwatch(int fd)
{
    socket_callback* cb;
    socket_callback* next;

    ASSERT(fd != -1);

    FD_CLR(fd, &ctx.read_fds);
    FD_CLR(fd, &ctx.write_fds);

    if(!ctx.callbacks)
        return;

    /* First in list */;
    if(ctx.callbacks->fd == fd)
    {
        cb = ctx.callbacks;
        ctx.callbacks = ctx.callbacks->next;
        free(cb);
    }

    if(!ctx.callbacks)
        return;

    /* One ahead processing of rest */
    cb = ctx.callbacks;
    while(cb->next)
    {
        if(cb->next->fd == fd)
        {
            next = cb->next;
            cb->next = cb->next->next;
            free(next);
        }
        else
        {
            cb = cb->next;
        }
    }
}

int
server_timer(int period_ms, server_timer_callback callback, void* arg)
{
    struct timeval interval;
    struct timeval at;
    struct timeval now;
    if (gettimeofday(&now, NULL) == -1) {
	err(1, "gettimeofday failed");
    }

    interval.tv_sec = period_ms / 1000;
    interval.tv_usec = (period_ms % 1000) * 1000; /* into micro seconds */

    at = now;
    timeradd(&at, &interval, &at);

    return add_timer(at, period_ms, callback, arg);
}

int
server_timer_at(struct timeval at, int period_ms, server_timer_callback callback, void* arg)
{
    return add_timer(at, period_ms, callback, arg);
}
