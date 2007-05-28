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

#include "usuals.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <err.h>
#include <arpa/inet.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>

#include "rrdbotd.h"
#include "server-mainloop.h"
#include "async-resolver.h"

/* The socket to use */
static int snmp_socket = -1;

/* The last request id */
static uint32_t snmp_request = 100000;

/* Since we only deal with one packet at a time, global buffer */
static unsigned char snmp_buffer[0x1000];

/* -----------------------------------------------------------------------------
 * REQUESTS
 */

typedef struct _rb_request
{
    /* The SNMP request identifier */
    uint32_t id;

    mstime next_retry;        /* Time of the next retry */
    mstime last_sent;         /* Time last sent */
    mstime interval;          /* How long between retries */
    mstime timeout;           /* When this request times out */
    uint sent;                /* How many times we've sent */

    /* The poller and host associated with this request */
    rb_poller* poll;
    const rb_host* host;

    /* The actual request data */
    struct snmp_pdu pdu;
}
rb_request;

/* a scrolling window on a loop */
static rb_request* requests = NULL;
static int reqhigh = -1;
static int reqlow = -1;
static uint nrequests = 0;

static rb_request*
new_req()
{
    rb_request* req = NULL;
    uint num;
    int i, overlap = 0;

    if(nrequests)
    {
        /* We allocate in a loop starting after the last allocation. */
        for(i = (reqhigh + 1) % nrequests; i != reqhigh;
            i = (i + 1) % nrequests)
        {
            /*
             * We can overlap past reqlow, but in that case no
             * updating reqhigh. This can happen after reallocating.
             */
            if(i == reqlow)
                overlap = 1;

            if(requests[i].id == 0)
            {
                req = &(requests[i]);

                if(!overlap)
                    reqhigh = i;
                break;
            }
        }
    }

    if(!req)
    {
        /*
         * A note about the scrolling window and extending allocations...
         * The only reason this works is because whenever we reallocate
         * reqhigh and reqlow are the same.
         */
        ASSERT(reqlow == reqhigh);

        /* Reallocate the request block */
        /* TODO: Once we use less memory this can be higher */
        num = nrequests ? nrequests * 2 : 32;
        requests = (rb_request*)realloc(requests, sizeof(rb_request) * num);
        if(!requests)
        {
            /* Note we leave old requests allocated */
            errno = ENOMEM;
            return NULL;
        }

        /* Clear out the new ones */
        memset(requests + nrequests, 0, sizeof(rb_request) * (num - nrequests));

        /* We return the next one */
        req = requests + nrequests;

        nrequests = num;

        if(reqhigh == -1)
            reqhigh = 0;
        if(reqlow == -1)
            reqlow = nrequests - 1;
    }

    /* A incrementing counter for each request */
    req->id = snmp_request++;
    return req;
}

static rb_request*
find_req(uint32_t id)
{
    int i, first;

    if(!nrequests)
        return NULL;

    /*
     * Search backwards from the in the scrolling window. This gives
     * us as high performance for the high performing pollers and
     * less performance for the low ones.
     */
    for(i = reqhigh, first = 1; first || i != reqlow;
        i = (i ? i : nrequests) - 1)
    {
        if(id == requests[i].id)
            return &(requests[i]);
        first = 0;
    }

    return NULL;
}

static void
free_req(rb_request* req)
{
    int i;

    memset(req, 0, sizeof(*req));

    /* Update the bottom of the scrolling loop */
    for(i = reqlow; i != reqhigh; i = (i + 1) % nrequests)
    {
        /* If used then done */
        if(requests[i].id)
            break;

        /* reqlow is not inclusive */
        reqlow = i;
    }
}

/* -----------------------------------------------------------------------------
 * PACKET HANDLING
 */

static void
finish_poll(rb_poller* poll, mstime when)
{
#ifdef _DEBUG
    {
        rb_item* it;
        for(it = poll->items; it; it = it->next)
            ASSERT(!it->req);
    }
#endif

    /* Update the book-keeping */
    poll->last_polled = when;

    /* And send off our collection of values */
    rb_rrd_update(poll);
}

static void
send_req(rb_request* req, mstime when)
{
    struct asn_buf b;
    ssize_t ret;

    /* Update our bookkeeping */
    req->sent++;
    if(req->sent <= g_state.retries)
        req->next_retry = when + req->interval;
    else
        req->next_retry = 0;
    req->last_sent = when;

    /* No sending if no address */
    if(!req->host->is_resolved)
    {
        if(req->sent <= 1)
            rb_messagex(LOG_DEBUG, "skipping snmp request: host not resolved: %s",
                        req->host->hostname);
        return;
    }

    b.asn_ptr = snmp_buffer;
    b.asn_len = sizeof(snmp_buffer);

    if(snmp_pdu_encode(&(req->pdu), &b))
        rb_message(LOG_CRIT, "couldn't encode snmp buffer");
    else
    {
        ret = sendto(snmp_socket, snmp_buffer, b.asn_ptr - snmp_buffer, 0,
                     &SANY_ADDR(req->host->address), SANY_LEN(req->host->address));
        if(ret == -1)
            rb_message(LOG_ERR, "couldn't send snmp packet to: %s", req->host->hostname);
        else
            rb_messagex(LOG_DEBUG, "sent request #%d to: %s", req->id, req->host->hostname);
    }
}

static void
timeout_req(rb_request* req, mstime when)
{
    rb_poller* poll = req->poll;
    int incomplete = 0;
    rb_item* it;

    ASSERT(poll);

    /*
     * Marks of this requests items as unknown. Request is
     * over, free. See if poller is done
     */

    for(it = poll->items; it; it = it->next)
    {
        if(it->req == req)
        {
            rb_messagex(LOG_DEBUG, "value for field '%s' timed out", it->rrdfield);
            it->vtype = VALUE_UNSET;
            it->req = NULL;
        }

        else if(it->req)
            incomplete = 1;
    }

    /* For timeouts we use the time the last request was sent */
    when = req->last_sent;

    free_req(req);

    if(!incomplete)
        finish_poll(poll, when);
}

static void
check_req(rb_request* req, mstime when)
{
    ASSERT(req->id);

    /* See if it's timed out */
    if(when >= req->timeout)
        timeout_req(req, when);

    if(!req->next_retry)
        return;

    /* Resend if necessary */
    if(when >= req->next_retry)
        send_req(req, when);
}

static void
respond_req(rb_request* req, struct snmp_pdu* pdu, mstime when)
{
    struct snmp_value* value;
    rb_poller* poll = req->poll;
    rb_item* item;
    int i;

    ASSERT(req->id == pdu->request_id);

    for(i = 0; i < pdu->nbindings; i++)
    {
        value = &(pdu->bindings[i]);

        for(item = poll->items; item; item = item->next)
        {
            if(asn_compare_oid(&(value->var), &(item->snmpfield.var)) == 0)
            {
                const char *msg = NULL;
                switch(value->syntax)
                {
                case SNMP_SYNTAX_NULL:
                    item->vtype = VALUE_UNSET;
                    break;
                case SNMP_SYNTAX_INTEGER:
                    item->v.i_value = value->v.integer;
                    item->vtype = VALUE_REAL;
                    break;
                case SNMP_SYNTAX_COUNTER:
                case SNMP_SYNTAX_GAUGE:
                case SNMP_SYNTAX_TIMETICKS:
                    item->v.i_value = value->v.uint32;
                    item->vtype = VALUE_REAL;
                    break;
                case SNMP_SYNTAX_COUNTER64:
                    item->v.i_value = value->v.counter64;
                    item->vtype = VALUE_REAL;
                    break;
                case SNMP_SYNTAX_OCTETSTRING:
                case SNMP_SYNTAX_OID:
                case SNMP_SYNTAX_IPADDRESS:
                    msg = "snmp server returned non numeric value for field: %s";
                    break;
                case SNMP_SYNTAX_NOSUCHOBJECT:
                case SNMP_SYNTAX_NOSUCHINSTANCE:
                case SNMP_SYNTAX_ENDOFMIBVIEW:
                    msg = "field not available on snmp server: %s";
                    break;
                default:
                    msg = "snmp server returned invalid or unsupported value for field: %s";
                    break;
                }

                if(msg)
                    rb_messagex(LOG_WARNING, msg, item->rrdfield);
                else if(item->vtype == VALUE_REAL)
                    rb_messagex(LOG_DEBUG, "got value for field '%s': %lld",
                                item->rrdfield, item->v.i_value);
                else if(item->vtype == VALUE_FLOAT)
                    rb_messagex(LOG_DEBUG, "got value for field '%s': %.4lf",
                                item->rrdfield, item->v.f_value);
                else
                    rb_messagex(LOG_DEBUG, "got value for field '%s': U",
                                item->rrdfield);

                /* Mark this value as done */
                item->req = NULL;
                break;
            }
        }
    }

    /* We're done with this request */
    free_req(req);

    /* Now see if the entire request is done */
    for(item = poll->items; item; item = item->next)
    {
        if(item->req)
            return;
    }


    /* And if so then hand off */
    finish_poll(poll, when);
}

static int
poller_timer(mstime when, void* arg)
{
    rb_poller* poll = (rb_poller*)arg;
    const rb_host* last_host = NULL;
    rb_request* req = NULL;
    rb_item* it;

    /*
     * If the previous poll has not completed, then we count it
     * as a timeout.
     */
    for(it = poll->items; it; it = it->next)
    {
        if(it->req)
        {
            ASSERT(it->req->poll == poll);
            timeout_req(it->req, when);
        }

        /* timeout_req above should have cleared this */
        ASSERT(!it->req);
    }


    for(it = poll->items; it; it = it->next)
    {
        /*
         * We assume that the polled items are sorted by host. Done
         * in config.c. This allows us to fire off the least amount
         * of requests. Generate new requests when:
         *
         * - first or new host
         * - too many items in the same request
         */
        if(!req || it->host != last_host ||
           req->pdu.nbindings >= SNMP_MAX_BINDINGS)
        {
            /* Send off last request ... */
            if(req)
                send_req(req, when);

            /* ... and make a new one */
            req = new_req();
            if(!req)
            {
                rb_message(LOG_CRIT, "couldn't allocate a new snmp request");
                return 1;
            }

            req->poll = poll;
            req->host = it->host;

            /* rb_messagex(LOG_DEBUG, "preparing request #%d for: %s@%s",
                        req->id, req->host->community, req->host->name); */

            /* Setup the packet */
            strlcpy(req->pdu.community, req->host->community, sizeof(req->pdu.community));
            req->pdu.request_id = req->id;
            req->pdu.version = req->host->version;
            req->pdu.type = SNMP_PDU_GET;
            req->pdu.error_status = 0;
            req->pdu.error_index = 0;
            req->pdu.nbindings = 0;

            /* Send interval is 200 ms when poll interval is below 2 seconds */
            req->interval = (poll->interval <= 2000) ? 200L : 600L;

            /* Timeout is for the last packet sent, not first */
            req->timeout = when + (req->interval * ((mstime)g_state.retries)) + poll->timeout;
            req->sent = 0;

            last_host = it->host;
        }

        /* Add an item to this request */
        req->pdu.bindings[req->pdu.nbindings].var = it->snmpfield.var;
        req->pdu.bindings[req->pdu.nbindings].syntax = it->snmpfield.syntax;
        req->pdu.nbindings++;

        /* Mark item as active by this request */
        it->req = req;
        it->vtype = VALUE_UNSET;
    }

    if(req)
        send_req(req, when);

    return 1;
}


static void
receive_resp(int fd, int type, void* arg)
{
    char hostname[MAXPATHLEN];
    struct sockaddr_any from;
    struct snmp_pdu pdu;
    struct asn_buf b;
    rb_request* req;
    const char* msg;
    int len, ret;
    int32_t ip;

    ASSERT(snmp_socket == fd);

    /* Read in the packet */

    SANY_LEN(from) = sizeof(from);
    len = recvfrom(snmp_socket, snmp_buffer, sizeof(snmp_buffer), 0,
                   &SANY_ADDR(from), &SANY_LEN(from));
    if(len < 0)
    {
        if(errno != EAGAIN && errno != EWOULDBLOCK)
            rb_message(LOG_ERR, "error receiving snmp packet from network");
        return;
    }


    if(sock_any_ntop(&from, hostname, MAXPATHLEN, 0) == -1)
        strcpy(hostname, "[UNKNOWN]");

    /* Now parse the packet */

    b.asn_ptr = snmp_buffer;
    b.asn_len = len;

    ret = snmp_pdu_decode(&b, &pdu, &ip);
    if(ret != SNMP_CODE_OK)
    {
        rb_message(LOG_WARNING, "invalid snmp packet received from: %s", hostname);
        return;
    }

    /* It needs to match something we're waiting for */
    req = find_req(pdu.request_id);
    if(!req)
    {
        rb_messagex(LOG_DEBUG, "received extra or delayed packet from: %s", hostname);
        return;
    }

    /* Check for errors */
    if(pdu.error_status != SNMP_ERR_NOERROR)
    {
        msg = snmp_get_errmsg (pdu.error_status);
        if(msg)
            rb_messagex(LOG_ERR, "snmp error from host '%s': %s",
                        hostname, msg);
        else
            rb_messagex(LOG_ERR, "unknown snmp error from host '%s': %d",
                        hostname, pdu.error_status);
        return;
    }

    if(pdu.version != req->pdu.version)
        rb_message(LOG_WARNING, "wrong version snmp packet from: %s", hostname);

    /* Dispatch the packet */
    rb_messagex(LOG_DEBUG, "response to request #%d from: %s", req->id, hostname);
    respond_req(req, &pdu, server_get_time());
}

static int
resend_timer(mstime when, void* arg)
{
    int i, first;

    /* Search backwards through the scrolling window */
    for(i = reqhigh, first = 1; first || i != reqlow;
        i = (i ? i : nrequests) - 1, first = 0)
    {
        if(requests[i].id)
            check_req(&(requests[i]), when);
    }

    return 1;
}

static int
prep_timer(mstime when, void* arg)
{
    /*
     * We don't prepare all timers at exactly the same time
     * but we sort of randomly start the various timers. We're
     * going to be hitting these over and over again, so there's
     * lots of benefits to spreading them out randomly over a
     * few seconds.
     */

    rb_poller* poll;
    int next;

    /* All done? */
    if(!arg)
        return 0;

    poll = (rb_poller*)arg;
    if(server_timer(poll->interval, poller_timer, poll) == -1)
        rb_message(LOG_CRIT, "couldn't setup poller timer");

    /* Setup the next poller anywhere between 0 and 750 ms */
    next = rand() % 750;
    server_oneshot(next, prep_timer, poll->next);
    return 0;
}

static void
resolve_cb(int ecode, struct addrinfo* ai, void* arg)
{
    rb_host* host = (rb_host*)arg;

    if(ecode)
    {
        rb_messagex(LOG_WARNING, "couldn't resolve hostname: %s: %s", host->hostname,
                    gai_strerror(ecode));
        return;
    }

    /* A successful resolve */
    memcpy(&SANY_ADDR(host->address), ai->ai_addr, ai->ai_addrlen);
    SANY_LEN(host->address) = ai->ai_addrlen;
    host->last_resolved = server_get_time();
    host->is_resolved = 1;

    rb_messagex(LOG_DEBUG, "resolved host: %s", host->hostname);
}

static int
resolve_timer(mstime when, void* arg)
{
    rb_host* host;
    struct addrinfo hints;

    /* Go through hosts and see which ones need resolving */
    for(host = g_state.hosts; host; host = host->next)
    {
        /* No need to resolve? */
        if(!host->resolve_interval)
            continue;

        if(when - host->resolve_interval > host->last_resolve_try)
        {
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = PF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;

            /* Automatically strips port number */
            rb_messagex(LOG_DEBUG, "resolving host: %s", host->hostname);
            async_resolver_queue(host->hostname, "161", &hints, resolve_cb, host);
            host->last_resolve_try = when;
        }

        /* When the last 3 resolves have failed, set to unresolved */
        if(when - (host->resolve_interval * 3) > host->last_resolved)
            host->is_resolved = 0;
    }

    return 1;
}

void
rb_snmp_engine_init()
{
    struct sockaddr_in addr;
    rb_request* req;

    ASSERT(snmp_socket == -1);
    snmp_socket = socket(PF_INET, SOCK_DGRAM, 0);
    if(snmp_socket < 0)
        err(1, "couldn't open snmp socket");

    /* Get a random IPv4 UDP socket for client use */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;

    if(bind(snmp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        err(1, "couldn't listen on port");

    if (server_watch(snmp_socket, SERVER_READ, receive_resp, NULL) == -1)
        err(1, "couldn't listen on socket");

    /* Allocate some requests to make sure we have memory */
    req = new_req();
    if(!req)
        err(1, "out of memory");
    free_req(req);

    /* Start the preparation timers for setting up randomly */
    if(server_oneshot(100, prep_timer, g_state.polls) == -1)
        err(1, "couldn't setup timer");

    /* We fire off the resend timer every 1/5 second */
    if(server_timer(200, resend_timer, NULL) == -1)
        err(1, "couldn't setup timer");

    /* resolve timer goes once per second */
    if(server_timer(1000, resolve_timer, NULL) == -1)
        err(1, "couldn't setup timer");
}

void
rb_snmp_engine_uninit()
{
    if(snmp_socket != -1)
    {
        server_unwatch(snmp_socket);
        close(snmp_socket);
        snmp_socket = -1;
    }

    if(requests)
    {
        free(requests);
        nrequests = 0;
        reqhigh = 0;
        reqlow = 0;
    }
}
