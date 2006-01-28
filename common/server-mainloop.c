
#include "usuals.h"
#include <errno.h>
#include <sys/time.h>

#include "server-mainloop.h"

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

static void
timeval_add(struct timeval* t1, struct timeval* t2)
{
    ASSERT(t1->tv_usec < 1000000);
    ASSERT(t2->tv_usec < 1000000);

    t1->tv_sec += t2->tv_sec;
    t1->tv_usec += t2->tv_usec;
    if(t1->tv_usec >= 1000000)
    {
        t1->tv_usec -= 1000000;
        t1->tv_sec += 1;
    }
}

static void
timeval_subtract(struct timeval* t1, struct timeval* t2)
{
    ASSERT(t1->tv_usec < 1000000);
    ASSERT(t2->tv_usec < 1000000);

    t1->tv_sec -= t2->tv_sec;
    if(t1->tv_usec < t2->tv_usec)
    {
        t1->tv_usec += 1000000;
        t1->tv_sec -= 1;
    }
    t1->tv_usec -= t2->tv_usec;
}

static int
timeval_compare(struct timeval* t1, struct timeval* t2)
{
    ASSERT(t1->tv_usec < 1000000);
    ASSERT(t2->tv_usec < 1000000);

    if(t1->tv_sec > t2->tv_sec)
        return 1;
    else if(t1->tv_sec < t2->tv_sec)
        return -1;
    else
    {
        if(t1->tv_usec > t2->tv_usec)
            return 1;
        else if(t1->tv_usec < t2->tv_usec)
            return -1;
        else
            return 0;
    }
}

#define timeval_empty(tv) \
    ((tv)->tv_sec == 0 && (tv)->tv_usec == 0)

#define timeval_to_ms(tv) \
    ((((uint64_t)(tv).tv_sec) * 1000L) + (((uint64_t)(tv).tv_usec) / 1000L))

#define timeval_dump(tv) \
    (fprintf(stderr, "{ %d:%d }", (uint)((tv).tv_sec), (uint)((tv).tv_usec / 1000)))

static int
add_timer(int ms, int oneshot, server_timer_callback callback, void* arg)
{
    struct timeval interval;
    timer_callback* cb;

    ASSERT(ms > 0);
    ASSERT(callback != NULL);

    interval.tv_sec = ms / 1000;
    interval.tv_usec = (ms % 1000) * 1000; /* into micro seconds */

    cb = (timer_callback*)calloc(1, sizeof(*cb));
    if(!cb)
    {
        errno = ENOMEM;
        return -1;
    }

    if(gettimeofday(&(cb->at), NULL) == -1)
    {
        free(cb);
        return -1;
    }

    timeval_add(&(cb->at), &interval);

    if (oneshot)
        memset(&(cb->interval), 0, sizeof(cb->interval));
    else
        memcpy(&(cb->interval), &interval, sizeof(cb->interval));

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

    ctx.timers = NULL;
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
            if(timeval_compare(&current, &timcb->at) >= 0)
            {
                /* Convert to milliseconds, and make the call */
                r = (timcb->callback)(timeval_to_ms(current), timcb->arg);

                /* Reset timer if so desired */
                if (r == 1 && !timeval_empty(&timcb->interval))
                {
                    timeval_add(&timcb->at, &timcb->interval);

                    /* If the time has already passed, just use current time */
                    if(timeval_compare(&(timcb->at), &current) <= 0)
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
            if (!timeout || timeval_compare(&timcb->at, timeout) < 0)
                timeout = &timcb->at;

            timcb = timcb->next;
        }

        /* Convert to an offset */
        if(timeout)
        {
            memcpy(&tv, timeout, sizeof(tv));
            timeout = &tv;
            timeval_subtract(timeout, &current);
        }

        /* fprintf(stderr, "selecting with timeout: ");
           timeval_dump(timeout);
           fprintf(stderr, "\n"); */

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

    ASSERT(fd != -1);

    FD_CLR(fd, &ctx.read_fds);
    FD_CLR(fd, &ctx.write_fds);

    if(!ctx.callbacks)
        return;

    /* First in list */;
    if(ctx.callbacks->fd == fd)
    {
        cb = ctx.callbacks;
        ctx.callbacks = cb->next;
        free(cb);
        return;
    }

    /* One ahead processing of rest */
    for(cb = ctx.callbacks; cb->next; cb = cb->next)
    {
        if(cb->next->fd == fd)
        {
            cb->next = cb->next->next;
            free(cb->next);
            return;
        }
    }
}

int
server_timer(int ms, server_timer_callback callback, void* arg)
{
    return add_timer(ms, 0, callback, arg);
}

int
server_oneshot(int ms, server_timer_callback callback, void* arg)
{
    return add_timer(ms, 1, callback, arg);
}
