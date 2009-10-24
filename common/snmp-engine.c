/*
 * Copyright (c) 2008, Stefan Walter
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

#include "async-resolver.h"
#include "hash.h"
#include "log.h"
#include "server-mainloop.h"
#include "snmp-engine.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <err.h>
#include <arpa/inet.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>
#include <mib/mib-parser.h>

struct host;
struct request;

typedef uint64_t mstime;

/* Forward declarations */
static void request_release (struct request *req);

/* ------------------------------------------------------------------------------
 * HOSTS
 */

struct host {
	/* The hash key is hostname:options:community */
	char key[128];

	char *hostname;
	char *portnum;
	char *community;
	int version;

	mstime interval;

	/* Host resolving and book keeping */
	struct sockaddr_storage address;
	socklen_t address_len;
	mstime resolve_interval;
	mstime last_resolve_try;
	mstime last_resolved;
	int is_resolved;
	int is_resolving;
	int must_resolve;

	/* Requests that are queued of this host */
	struct request *prepared;

	/* Next in list of hosts */
	struct host *next;
};

/* All hosts we've allocated */
static struct host *host_list = NULL;

/* Hosts hashed by the host:version:community string */
static hsh_t *host_by_key = NULL;

static void
resolve_cb (int ecode, struct addrinfo* ai, void* arg)
{
	struct host *host = (struct host*)arg;
	host->is_resolving = 0;

	if (ecode) {
		log_warnx ("couldn't resolve host name: %s: %s",
		           host->hostname, gai_strerror (ecode));
		return;
	}

	if (ai->ai_addrlen > sizeof (host->address)) {
		log_warnx ("resolved address is too long for host name: %s",
		           host->hostname);
		return;
	}

	/* A successful resolve */
	memcpy (&host->address, ai->ai_addr, ai->ai_addrlen);
	host->address_len = ai->ai_addrlen;
	host->last_resolved = server_get_time ();
	host->is_resolved = 1;

	log_debug ("resolved host: %s", host->hostname);
}

static void
host_resolve (struct host *host, mstime when)
{
	struct addrinfo hints;

	if (host->is_resolving)
		return;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_NUMERICSERV;

	/* Automatically strips port number */
	log_debug ("resolving host: %s", host->hostname);
	host->last_resolve_try = when;
	host->is_resolving = 0;
	async_resolver_queue (host->hostname, host->portnum, &hints, resolve_cb, host);
}

static int
host_resolve_timer (mstime when, void* arg)
{
	struct host* h;

	/* Go through hosts and see which ones need resolving */
	for (h = host_list; h; h = h->next) {

		/* No need to resolve? */
		if (!h->must_resolve)
			continue;

		ASSERT (h->resolve_interval);

		if (when - h->resolve_interval > h->last_resolve_try)
			host_resolve (h, when);

		/* When the last 3 resolves have failed, set to unresolved */
		if (h->is_resolved && when - (h->resolve_interval * 3) > h->last_resolved) {
			log_debug ("host address expired, and was not resolved: %s", h->hostname);
			h->is_resolved = 0;
		}
	}

	return 1;
}

static void
host_update_interval (struct host *host, mstime interval)
{
	mstime resint;

	if (!host->must_resolve)
		return;

	/* When less than three minutes, resolve once per minute */
	if (interval <= 180000)
		resint = 60000;

	/* When between 3 and 10 minutes resolve once per cycle */
	else if(interval <= 600000)
		resint = interval;

	/* Otherwise resolve thrice per cycle */
	else
		resint = interval / 3;

        /* The lowest interval (since hosts can be shared by pollers) wins */
	if (!host->resolve_interval || host->resolve_interval > resint) {
		host->resolve_interval = resint;
		log_debug ("will resolve host '%s' every %d seconds", host->hostname, resint / 1000);
	}
}

static struct host*
host_instance (const char *hostname, const char *portnum,
               const char *community, int version, mstime interval)
{
	struct addrinfo hints, *ai;
	struct host *host;
	char key[128];
	int r, initialize;

	ASSERT (hostname);
	initialize = 0;

	if (!portnum)
		portnum = "161";

	/*
	 * Build a lookup key. We can only combine requests for the same
	 * host when the version and community match.
	 */
	community = community ? community : "public";
	snprintf (key, sizeof(key), "%s:%d:%s", hostname, version, community);
	key[sizeof(key) - 1] = 0;

	/* See if we can find an associated host */
	host = hsh_get (host_by_key, key, -1);
	if (!host) {

		memset (&hints, 0, sizeof (hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICSERV | AI_NUMERICHOST;

		r = getaddrinfo (hostname, portnum, &hints, &ai);

		/* Ignore error and try to resolve again later */
		if (r == EAI_NONAME || r == EAI_AGAIN || r == EAI_MEMORY) {
			ai = NULL;

		/* Real errors */
		} else if (r != 0) {
			log_warnx ("couldn't parse host address (ignoring): %s: %s",
			           hostname, gai_strerror (r));
			return NULL;

		/* Strango address */
		} else if (ai->ai_addrlen > sizeof (host->address)) {
			log_warnx ("parsed host address is too big (ignoring): %s", hostname);
			return NULL;
		}

		host = calloc (1, sizeof (struct host));
		if (!host) {
			log_errorx ("out of memory");
			if (ai != NULL)
				freeaddrinfo (ai);
			return NULL;
		}

		if (ai != NULL) {
			memcpy (&host->address, ai->ai_addr, ai->ai_addrlen);
			host->address_len = ai->ai_addrlen;
			freeaddrinfo (ai);
			host->must_resolve = 0;
			host->is_resolved = 1;
		} else {
			host->must_resolve = 1;
			host->is_resolved = 0;
		}

		/* And into the hash table */
		memcpy (&host->key, key, sizeof (host->key));
		if (!hsh_set (host_by_key, host->key, -1, host)) {
			log_errorx ("out of memory");
			free (host);
			return NULL;
		}

		/* And add it to the list */
		host->next = host_list;
		host_list = host;

		host->version = version;
		host->hostname = strdup (hostname);
		host->portnum = strdup (portnum);
		host->community = strdup (community);
		host->resolve_interval = 0;
		host->last_resolved = 0;
		host->last_resolve_try = 0;

		/* Start the resolving process */
		if (!host->is_resolved)
			host_resolve (host, server_get_time ());
	}

	/* Update the host's resolve interval based on the poll interval requested */
	host_update_interval (host, interval);

	return host;
}

static void
host_initialize (void)
{
	/* Initialize stuff if necessary */
	host_by_key = hsh_create ();
	if (!host_by_key)
		err (1, "out of memory");

	/* resolve timer goes once per second */
	if (server_timer (1000, host_resolve_timer, NULL) == -1)
		err (1, "couldn't setup resolve timer");
}

static void
host_cleanup (void)
{
	struct host *next, *host;

	if (host_by_key)
		hsh_free (host_by_key);
	host_by_key = NULL;

	for (host = host_list; host; host = next) {
		next = host->next;
		if (host->hostname)
			free (host->hostname);
		if (host->portnum)
			free (host->portnum);
		if (host->community)
			free (host->community);
		if (host->prepared)
			request_release (host->prepared);
		free (host);
	}

	host_list = NULL;
}

/* ------------------------------------------------------------------------------
 * ASYNC REQUEST PROCESSING
 */

#define MAKE_REQUEST_ID(snmp, cb) \
	((((snmp) & 0xFFFFFF) << 8) | (cb & 0xFF))
#define REQUEST_ID_SNMP(id) \
	((id) >> 8)
#define REQUEST_ID_CB(id) \
	((id) & 0xFF)

struct request
{
	/* The SNMP request identifier */
	uint snmp_id;

	/* References, useful since we have callbacks */
	int refs;

	mstime next_send;         /* Time of the next packet send */
	mstime last_sent;         /* Time last sent */
	mstime retry_interval;    /* How long between retries */
	mstime when_timeout;      /* When this request times out */
	uint num_sent;            /* How many times we've sent */

	struct host *host;        /* Host associated with this request */

	/* One callback entry for each binding */
	struct {
		snmp_response func;
		void *arg;
	} callbacks[SNMP_MAX_BINDINGS];

	/* The actual request data */
	struct snmp_pdu pdu;
};

struct socket
{
	int fd;                         /* The SNMP socket we're communicating on */
	struct sockaddr_storage addr;   /* Local address of this socket */
	socklen_t addr_len;             /* Length of addr */
	struct socket *next;            /* Linked list of socket structures */
};

/* The number of SNMP packet retries */
static int snmp_retries = 3;

/* The last request id */
static uint snmp_request_id = 1;

/* The sockets we communicate on */
static struct socket *snmp_sockets = NULL;

/* Since we only deal with one packet at a time, global buffer */
static unsigned char snmp_buffer[0x1000];

/* Hash table of all requests being processed */
static hsh_t *snmp_processing = NULL;

/* Hash table of all requests being prepared */
static hsh_t *snmp_preparing = NULL;

/* A flush of prepared packets is pending */
static int snmp_flush_pending = 0;

static void
request_release (struct request *req)
{
	/* It should no longer be referred to any of these places */
	ASSERT (!hsh_get (snmp_preparing, &req->snmp_id, sizeof (req->snmp_id)));
	ASSERT (!hsh_get (snmp_processing, &req->snmp_id, sizeof (req->snmp_id)));

	snmp_pdu_clear (&req->pdu);
	free (req);
}

static void
request_send (struct request* req, mstime when)
{
	struct socket* sock;
	struct asn_buf b;
	ssize_t ret;

	assert (snmp_sockets != NULL);

	/* Update our bookkeeping */
	req->num_sent++;
	if (req->num_sent <= snmp_retries)
		req->next_send = when + req->retry_interval;
	else
		req->next_send = 0;
	req->last_sent = when;

	if (!req->host->is_resolved) {
		if (req->num_sent <= 1)
			log_debug ("skipping snmp request: host not resolved: %s",
			           req->host->hostname);
		return;
	}

	/* Select a good socket to use, based on address family */
	for (sock = snmp_sockets; sock; sock = sock->next) {
		if (sock->addr.ss_family == req->host->address.ss_family)
			break;
	}

	if (sock == NULL) {
		log_warnx ("couldn't send snmp packet to: %s: %s",
		           req->host->hostname, "no local address of relevant protocol family");
		return;
	}

	b.asn_ptr = snmp_buffer;
	b.asn_len = sizeof (snmp_buffer);

	if (snmp_pdu_encode (&req->pdu, &b)) {
		log_error("couldn't encode snmp buffer");
	} else {
		ret = sendto (sock->fd, snmp_buffer, b.asn_ptr - snmp_buffer, 0,
		              (struct sockaddr*)&req->host->address, req->host->address_len);
		if (ret == -1)
			log_error ("couldn't send snmp packet to: %s", req->host->hostname);
		else
			log_debug ("sent request #%d to: %s", req->snmp_id, req->host->hostname);
	}
}

static void
request_failure (struct request *req, int code)
{
	void *val;
	int j;

	ASSERT (req);
	ASSERT (code != 0);
	ASSERT (hsh_get (snmp_processing, &req->snmp_id, sizeof (req->snmp_id)) == req);

	log_debug ("failed request #%d to '%s' with code %d", req->snmp_id, req->host->hostname, code);

	/* For each request SNMP value... */
	for (j = 0; j < req->pdu.nbindings; ++j) {

		if (!req->callbacks[j].func)
			continue;

		/* ... let callback know */
		(req->callbacks[j].func) (MAKE_REQUEST_ID (req->snmp_id, j),
				          code, NULL, req->callbacks[j].arg);

		/*
		 * Request could have been freed by the callback, by calling the cancel
		 * function, check and bail if so.
		 */
		if (hsh_get (snmp_processing, &req->snmp_id, sizeof (req->snmp_id)) != req)
			return;
	}

	/* Remove from the processing list */
	val = hsh_rem (snmp_processing, &req->snmp_id, sizeof (req->snmp_id));
	ASSERT (val == req);

	/* And free the request */
	request_release (req);
}

static void
request_get_dispatch (struct request* req, struct snmp_pdu* pdu)
{
	struct snmp_value* pvalue;
	struct snmp_value* rvalue;
	int i, j, skipped, processed;
	void *val;

	ASSERT (req);
	ASSERT (pdu);
	ASSERT (req->snmp_id == pdu->request_id);
	ASSERT (pdu->error_status == SNMP_ERR_NOERROR);
	ASSERT (req->pdu.type == SNMP_PDU_GET);
	ASSERT (hsh_get (snmp_processing, &req->snmp_id, sizeof (req->snmp_id)) == req);

	/*
	 * For SNMP GET requests we check that the values that came back
	 * were in fact for the same values we requested, and fix any
	 * ordering issues etc.
	 */
	skipped = 0;
	for (j = 0; j < SNMP_MAX_BINDINGS; ++j) {

		if (!req->callbacks[j].func)
			continue;

		rvalue = &(req->pdu.bindings[j]);
		processed = 0;

		/* ... dig out matching value from response */
		for (i = 0; i < pdu->nbindings; ++i) {
			pvalue = &(pdu->bindings[i]);

			if (asn_compare_oid (&(rvalue->var), &(pvalue->var)) != 0)
				continue;

			(req->callbacks[j].func) (MAKE_REQUEST_ID (req->snmp_id, j),
			                          SNMP_ERR_NOERROR, pvalue, req->callbacks[j].arg);

			/*
			 * Request could have been freed by the callback, by calling the cancel
			 * function, check and bail if so.
			 */
			if (hsh_get (snmp_processing, &req->snmp_id, sizeof (req->snmp_id)) != req)
				return;

			req->callbacks[j].func = NULL;
			processed = 1;
			break;
		}

		/* Make note that we didn't find a match for at least one binding */
		if (!processed && !skipped)
			skipped = 1;
	}

	/* All done? then remove request */
	if (!skipped) {

		log_debug ("request #%d is complete", req->snmp_id);

		val = hsh_rem (snmp_processing, &req->snmp_id, sizeof (req->snmp_id));
		ASSERT (val == req);
		request_release (req);
	}
}

static void
request_other_dispatch (struct request* req, struct snmp_pdu* pdu)
{
	void *val;

	ASSERT (req);
	ASSERT (pdu);
	ASSERT (req->snmp_id == pdu->request_id);
	ASSERT (pdu->error_status == SNMP_ERR_NOERROR);
	ASSERT (req->pdu.type != SNMP_PDU_GET);

	/*
	 * For requests other than GET we just use the first value
	 * that was sent. See below where we limit to one binding
	 * per SNMP request when other than GET.
	 */

	if (pdu->nbindings == 0) {
		log_warn ("received response from the server without any values");
		return;
	}

	if (pdu->nbindings > 1)
		log_warn ("received response from the server with extra values");

	/* Shouldn't have sent more than one binding */
	ASSERT (req->pdu.nbindings == 1);

	if (req->callbacks[0].func)
		(req->callbacks[0].func) (MAKE_REQUEST_ID (req->snmp_id, 0), SNMP_ERR_NOERROR,
				          &(pdu->bindings[0]), req->callbacks[0].arg);

	log_debug ("request #%d is complete", req->snmp_id);

	val = hsh_rem (snmp_processing, &req->snmp_id, sizeof (req->snmp_id));
	ASSERT (val == req);
	request_release (req);
}

static void
request_response (int fd, int type, void* arg)
{
	struct sockaddr_storage from;
	char hostname[MAXPATHLEN];
	struct snmp_pdu pdu;
	struct asn_buf b;
	struct request* req;
	const char* msg;
	socklen_t from_len;
	int len, ret;
	int ip, id;

	/* Read in the packet */
	from_len = sizeof (from);
	len = recvfrom (fd, snmp_buffer, sizeof (snmp_buffer), 0,
	                (struct sockaddr*)&from, &from_len);
	if(len < 0) {
		if(errno != EAGAIN && errno != EWOULDBLOCK)
			log_error ("error receiving snmp packet from network");
		return;
	}

	if (getnameinfo ((struct sockaddr*)&from, from_len,
	                 hostname, sizeof (hostname), NULL, 0,
	                 NI_NUMERICHOST) != 0)
		strcpy (hostname, "[UNKNOWN]");

	/* Now parse the packet */

	b.asn_ptr = snmp_buffer;
	b.asn_len = len;

	ret = snmp_pdu_decode(&b, &pdu, &ip);
	if (ret != SNMP_CODE_OK) {
		log_warnx ("invalid snmp packet received from: %s", hostname);
		return;
	}

	/* It needs to match something we're waiting for */
	id = pdu.request_id;
	req = hsh_get (snmp_processing, &id, sizeof (id));
	if(!req) {
		log_debug ("received extra, cancelled or delayed packet from: %s", hostname);
		snmp_pdu_clear (&pdu);
		return;
	}

	if(pdu.version != req->pdu.version)
		log_warnx ("wrong version snmp packet from: %s", hostname);


	/* Log any errors */
	if(pdu.error_status == SNMP_ERR_NOERROR) {
		log_debug ("response to request #%d from: %s", req->snmp_id, hostname);

		if (req->pdu.type == SNMP_PDU_GET)
			request_get_dispatch (req, &pdu);
		else
			request_other_dispatch (req, &pdu);

	} else {
		msg = snmp_get_errmsg (pdu.error_status);
		if(msg)
			log_debug ("failure for request #%d from: %s: %s", req->snmp_id, hostname, msg);
		else
			log_debug ("failure for request #%d from: %s: %d", req->snmp_id, hostname,
			           pdu.error_status);
		request_failure (req, pdu.error_status);
	}

	snmp_pdu_clear (&pdu);
}

static void
request_process_all (mstime when)
{
	struct request *req;
	hsh_index_t *i;

	/* Go through all processing packets */
	for (i = hsh_first (snmp_processing); i; ) {

		req = hsh_this (i, NULL, NULL);
		ASSERT (req);

		/* Move to the next, as we may delete below */
		i = hsh_next (i);

		if (when >= req->when_timeout) {
			request_failure (req, -1);
			continue;
		}

		if (req->next_send && when >= req->next_send)
			request_send (req, when);
	}
}

static int
request_resend_timer (mstime when, void* arg)
{
	request_process_all (when);
	return 1;
}

static void
request_flush (struct request *req, mstime when)
{
	void *val;

	ASSERT (req->host->prepared == req);

	val = hsh_rem (snmp_preparing, &req->snmp_id, sizeof (req->snmp_id));
	ASSERT (val == req);

	/* Don't let us add more onto this request via the host */
	ASSERT (req->host->prepared == req);
	req->host->prepared = NULL;

	/* Mark this packet to be sent now */
	req->next_send = when;

	if (!hsh_set (snmp_processing, &req->snmp_id, sizeof (req->snmp_id), req)) {
		log_errorx ("out of memory, discarding packets");
		request_release (req);
	}
}

static void
request_flush_all (mstime when)
{
	struct request *req;
	hsh_index_t *i;

	/* Transfer everything to the processing table */
	for (i = hsh_first (snmp_preparing); i; ) {
		req = hsh_this (i, NULL, NULL);

		/* Do this here, because below removes from table */
		i = hsh_next (i);

		request_flush (req, when);
	}

	/* Clear the preparing table */
	hsh_clear (snmp_preparing);

	/* Process all packets in processing */
	request_process_all (when);
}



static int
request_flush_cb (mstime when, void *arg)
{
	snmp_flush_pending = 0;
	request_flush_all (when);
	return 0;
}

static struct request*
request_prep_instance (struct host *host, mstime interval, mstime timeout, int reqtype)
{
	struct request *req;

	/* See if we have one we can piggy back onto */
	req = host->prepared;
	if (req) {
		ASSERT (hsh_get (snmp_preparing, &req->snmp_id, sizeof (req->snmp_id)));

		/* We have one we can piggy back another request onto */
		if (req->pdu.nbindings < SNMP_MAX_BINDINGS && req->pdu.type == reqtype)
			return req;

		/* It's too full, so send it off */
		request_flush (req, server_get_time ());
		req = NULL;
	}

	ASSERT (host->prepared == NULL);

	/* Create a new request */
	req = calloc (1, sizeof (struct request));
	if (!req) {
		log_error ("out of memory");
		return NULL;
	}

	/* Assign the unique id */
	req->snmp_id = snmp_request_id++;

	/* Roll around after a decent amount of ids */
	if (snmp_request_id >= 0xFFFFFF)
		snmp_request_id = 1;

	/* Mark it down as something we want to prepare */
	if (!hsh_set (snmp_preparing, &req->snmp_id, sizeof (req->snmp_id), req)) {
		log_error ("out of memory");
		free (req);
		return NULL;
	}

        /* Setup the packet */
        strlcpy (req->pdu.community, host->community, sizeof (req->pdu.community));
        req->pdu.request_id = req->snmp_id;
        req->pdu.version = host->version;
        req->pdu.type = reqtype;
        req->pdu.error_status = 0;
        req->pdu.error_index = 0;
        req->pdu.nbindings = 0;

        /* Send interval is 200 ms when poll interval is below 2 seconds */
        req->retry_interval = (interval <= 2000) ? 200L : 600L;

        /* Timeout is for the last packet sent, not first */
        req->when_timeout = server_get_time () + (req->retry_interval * ((mstime)snmp_retries)) + timeout;
        req->num_sent = 0;

        /* Add it to the host */
	req->host = host;
	ASSERT (host->prepared == NULL);
        host->prepared = req;

        log_debug ("preparing request #%d for: %s@%s", req->snmp_id,
                   req->host->community, req->host->hostname);

	return req;
}

int
snmp_engine_request (const char *hostname, const char *port,
                     const char *community, int version,
                     mstime interval, mstime timeout, int reqtype,
                     struct asn_oid *oid, snmp_response func, void *arg)
{
	struct host *host;
	struct request *req;
	int callback_id;

	ASSERT (func);

	/* Lookup host for request */
	host = host_instance (hostname, port, community, version, interval);
	if (!host)
		return 0;

	/* Get a request with space or a new request for that host */
	req = request_prep_instance (host, interval, timeout, reqtype);
	if (!req)
		return 0;

	ASSERT (req->pdu.nbindings < SNMP_MAX_BINDINGS);

	/* Add the oid to that request */
	callback_id = req->pdu.nbindings;
        req->pdu.bindings[callback_id].var = *oid;
        req->pdu.bindings[callback_id].syntax = SNMP_SYNTAX_NULL;
        req->callbacks[callback_id].func = func;
        req->callbacks[callback_id].arg = arg;
        req->pdu.nbindings++;

        /* All other than GET, only get one binding */
        if (reqtype != SNMP_PDU_GET) {
        	ASSERT (req->pdu.nbindings == 1);
        	request_flush (req, server_get_time ());
        }

        /* Otherwise flush on the idle callback */
        else if (!snmp_flush_pending) {
        	server_oneshot (0, request_flush_cb, NULL);
        	snmp_flush_pending = 1;
        }

        return MAKE_REQUEST_ID (req->snmp_id, callback_id);
}

void
snmp_engine_cancel (int id)
{
	struct request *req;
	int snmp_id, callback_id, i;
	const char *during;

	ASSERT (id);

	snmp_id = REQUEST_ID_SNMP (id);
	callback_id = REQUEST_ID_CB (id);

	ASSERT (snmp_id > 0 && snmp_id < 0xFFFFFF);
	ASSERT (callback_id >= 0 && callback_id < SNMP_MAX_BINDINGS);

	/* Is it being processed? */
	req = hsh_rem (snmp_processing, &snmp_id, sizeof (snmp_id));
	if (req) {
		during = "processing";

	/* Is it being prepared? */
	} else {
		req = hsh_rem (snmp_preparing, &snmp_id, sizeof (snmp_id));
		if (req) {
			during = "prep";
			ASSERT (req->host->prepared == req);
		}
	}

	if (!req)
		return;

	/* Remove this callback from the request */
	req->callbacks[callback_id].func = NULL;
	req->callbacks[callback_id].arg = NULL;

	/* See if any callbacks exist in the request */
	for (i = 0; i < SNMP_MAX_BINDINGS; ++i) {
		if (req->callbacks[i].func)
			return;
	}

	/* If not, free the request */
	log_debug ("cancelling request #%d during %s", snmp_id, during);
	if (req->host->prepared == req)
		req->host->prepared = NULL;
	request_release (req);
}

void
snmp_engine_flush (void)
{
	request_flush_all (server_get_time ());
}

/* -------------------------------------------------------------------------------
 * SYNC REQUESTS
 */

struct sync_data {
	int valid;
	int code;
	int id;
	struct snmp_value *dest;
};

static void
sync_response (int req, int code, struct snmp_value *value, void *data)
{
	struct sync_data *sync = data;

	ASSERT (req == sync->id);

	sync->valid = 1;
	sync->code = code;
	if (value)
		snmp_value_copy (sync->dest, value);

	server_stop ();
}

int
snmp_engine_sync (const char* host, const char *port, const char* community,
                  int version, uint64_t interval, uint64_t timeout, int reqtype,
                  struct snmp_value *value)
{
	struct sync_data sync;

	/* Can't run a sync request with the server running */
	ASSERT (server_stopped());

	sync.valid = 0;
	sync.code = 0;
	sync.dest = value;

	sync.id = snmp_engine_request (host, port, community, version, interval, timeout,
	                               reqtype, &value->var, sync_response, &sync);

	if (!sync.id)
		return -1;

	snmp_engine_flush ();
	server_run ();

	ASSERT (sync.valid);
	return sync.code;
}

/* -----------------------------------------------------------------------------
 * INIT
 */

void
snmp_engine_init (const char **bindaddrs, int retries)
{
	struct addrinfo hints, *ai;
	struct socket *sock;
	const char **p, *bindaddr;
	int fd, r;

	assert (bindaddrs);

	snmp_retries = retries;

	snmp_processing = hsh_create ();
	if (!snmp_processing)
		err (1, "out of memory");

	snmp_preparing = hsh_create ();
	if (!snmp_preparing)
		err (1, "out of memory");

	assert (snmp_sockets == NULL);

	for (p = bindaddrs; p && *p; ++p) {
		bindaddr = *p;

		memset (&hints, 0, sizeof (hints));
		hints.ai_flags = AI_PASSIVE;
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_NUMERICSERV;
		r = getaddrinfo (bindaddr, "0", &hints, &ai);
		if (r != 0)
			errx (1, "couldn't resolve bind address: %s: %s", bindaddr, gai_strerror (r));

		fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			err (1, "couldn't open snmp socket");

		if (bind (fd, ai->ai_addr, ai->ai_addrlen) < 0)
			err (1, "couldn't listen on port");

		if (server_watch (fd, SERVER_READ, request_response, NULL) == -1)
			err (1, "couldn't listen on socket");

		/* Stash this socket info */
		sock = xcalloc (sizeof (struct socket));
		sock->fd = fd;

		if (ai->ai_addrlen > sizeof (sock->addr))
			errx (1, "resolve address is too big");
		memcpy (&sock->addr, ai->ai_addr, ai->ai_addrlen);

		/* Push onto the linked list */
		sock->next = snmp_sockets;
		snmp_sockets = sock;

		freeaddrinfo (ai);
	}

	/* We fire off the resend timer every 1/5 second */
	if (server_timer (200, request_resend_timer, NULL) == -1)
	    err(1, "couldn't setup timer");

	host_initialize ();
}

void
snmp_engine_stop (void)
{
	struct socket *sock;

	while (snmp_sockets != NULL) {
		/* Pop off the list */
		sock = snmp_sockets;
		snmp_sockets = sock->next;

		/* And destroy */
		server_unwatch (sock->fd);
		close (sock->fd);
		free (sock);
	}

	host_cleanup ();
}

int
snmp_engine_match (const struct snmp_value *value, const char *text)
{
	char *end;

	ASSERT (value);
	ASSERT (text);

	switch (value->syntax) {

	/* Empty string */
	case SNMP_SYNTAX_NULL:
	case SNMP_SYNTAX_NOSUCHOBJECT:
	case SNMP_SYNTAX_NOSUCHINSTANCE:
	case SNMP_SYNTAX_ENDOFMIBVIEW:
		return *text == '\0';

	/* Integer value */
	case SNMP_SYNTAX_INTEGER:
		{
			int num = strtoll (text, &end, 0);
			if (*end != '\0')
				return 0;
			return num == value->v.integer;
		}

	/* String of bytes */
	case SNMP_SYNTAX_OCTETSTRING:
		{
			int len = strlen (text);
			if (value->v.octetstring.len != len)
				return 0;
			return memcmp (value->v.octetstring.octets, text, len) == 0;
		}


	case SNMP_SYNTAX_OID:
		{
			struct asn_oid oid;
			if (mib_parse (text, &oid) < 0)
				return 0;
			return asn_compare_oid (&oid, &value->v.oid) == 0;
		}

	case SNMP_SYNTAX_IPADDRESS:
		{
		    struct in_addr addr;
		    if (!inet_aton (text, &addr))
			    return 0;
		    return memcmp (&addr, value->v.ipaddress, 4) == 0;
		}

	case SNMP_SYNTAX_COUNTER:
	case SNMP_SYNTAX_GAUGE:
	case SNMP_SYNTAX_TIMETICKS:
		{
			uint64_t sub = strtoull (text, &end, 0);
			if (*end != '\0' || sub > 0xffffffff)
				return 0;
			return sub == value->v.uint32;
		}

	case SNMP_SYNTAX_COUNTER64:
		{
			uint64_t sub = strtoull (text, &end, 0);
			if (*end != '\0' || sub > 0xffffffff)
				return 0;
			return sub == value->v.counter64;
		}

	default:
		return 0;
	};
}
