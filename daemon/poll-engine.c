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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <err.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>

#include "log.h"
#include "rrdbotd.h"
#include "server-mainloop.h"
#include "snmp-engine.h"

/* -----------------------------------------------------------------------------
 * PACKET HANDLING
 */

static void
complete_request (rb_item *item, int code)
{
	int host;

	ASSERT (item);

	if (item->request)
		snmp_engine_cancel (item->request);
	item->request = 0;

	/* If we have multiple host names then try the next host */
	if (code != SNMP_ERR_NOERROR) {
		host = (item->hostindex + 1) % item->n_hostnames;
		if (host != item->hostindex) {
			log_debug ("request failed, trying new host: %s", item->hostnames[host]);
			item->hostindex = host;
		}
	}
}

static void
cancel_request (rb_item *item, const char *reason)
{
	ASSERT (item);
	ASSERT (reason);
	ASSERT (item->request);

        log_debug ("value for field '%s': %s", item->field, reason);
        item->vtype = VALUE_UNSET;

        complete_request (item, -1);
}

static void
force_poll (rb_poller *poll, mstime when, const char *reason)
{
	rb_item *item;
	int forced = 0;

	ASSERT (poll);
	ASSERT (reason);

	/* Now see if the entire request is done */
	for (item = poll->items; item; item = item->next) {
		if (item->request) {
			cancel_request (item, reason);
			forced = 1;
		}
		ASSERT (!item->request);
	}

	if (forced) {

		/*
		 * We note the failure has having taken place halfway between
		 * the request and the current time.
		 */
		poll->last_polled = poll->last_request + ((when - poll->last_request) / 2);

		/* And send off our collection of values */
		rb_rrd_update (poll);
	}
}

static void
finish_poll (rb_poller *poll, mstime when)
{
	rb_item *item;

	ASSERT (poll);

	/* Now see if the entire request is done */
	for (item = poll->items; item; item = item->next) {
		if (item->request)
			return;
	}

	/* Update the book-keeping */
	poll->last_polled = when;

	/* And send off our collection of values */
	rb_rrd_update (poll);
}

static void
field_response (int request, int code, struct snmp_value *value, void *arg)
{
	rb_item *item = arg;
	const char *msg = NULL;

	ASSERT (item->request == request);

	/* Mark this item as done */
	item->request = 0;

	/* Errors result in us writing U */
	if (code != SNMP_ERR_NOERROR) {
		item->vtype = VALUE_UNSET;

	/* Parse the value from server */
	} else {
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
		};

		if (msg)
			log_warnx (msg, item->field);
                else if (item->vtype == VALUE_REAL)
                	log_debug ("got value for field '%s': %lld",
                	           item->field, item->v.i_value);
                else if (item->vtype == VALUE_FLOAT)
		        log_debug ("got value for field '%s': %.4lf",
		                   item->field, item->v.f_value);
                else
                	log_debug ("got value for field '%s': U",
                	           item->field);
	}

	complete_request (item, code);

	/* If the entire poll is done, then complete it */
	finish_poll (item->poller, server_get_time ());
}

static void
field_request (rb_item *item)
{
	int req;

	ASSERT (item);
	ASSERT (!item->request);

        item->vtype = VALUE_UNSET;

	req = snmp_engine_request (item->hostnames[item->hostindex], item->community,
	                           item->version, item->poller->interval, item->poller->timeout,
	                           SNMP_PDU_GET, &item->field_oid, field_response, item);
	item->request = req;
}

/* Forward declaration */
static void query_request (rb_item *item, int first);

static void
query_response (int request, int code, struct snmp_value *value, void *arg)
{
	rb_item *item = arg;
	struct asn_oid oid;
	int matched, req, found;

	ASSERT (request == item->request);
	ASSERT (item->has_query);

	/*
	 * This was the number we last appended.
	 */
	ASSERT (item->query_value >= 0);
	item->request = 0;

	/* Problems communicating with the server? */
	if (code != SNMP_ERR_NOERROR && code != SNMP_ERR_NOSUCHNAME) {
		complete_request (item, code);
		return;
	}

	found = 0;
	matched = 0;

	if (code == SNMP_ERR_NOERROR) {
		ASSERT (value);

		/* These all signify 'not found' in our book */
		switch (value->syntax) {
		case SNMP_SYNTAX_NOSUCHOBJECT:
		case SNMP_SYNTAX_NOSUCHINSTANCE:
		case SNMP_SYNTAX_ENDOFMIBVIEW:
			found = 0;
			matched = 0;
			break;

		/* See if we have a match */
		default:
			if (item->query_match)
				matched = snmp_engine_match (value, item->query_match);

			/* When query match is null, anything matches */
			else
				matched = 1;

			found = 1;
			break;
		};
	}

	/*
	 * When we had found this before, but then can no longer find it, we
	 * start search again from the base.
	 */
	if (!matched && item->query_last != 0) {
		log_debug ("last table index did not match, starting from zero");
		item->query_last = 0;
		query_request (item, 1);

	/*
	 * When we find no value at zero, then we skip ahead and see if
	 * perhaps its a one based table
	 */
	} else if (!found && item->query_value == 0) {
		log_debug ("no zero index in table, trying index one");
		item->query_last = 0;
		query_request (item, 0);

	/*
	 * Any other time we don't find a value, its game over for us,
	 * we didn't find a match and are out of values.
	 */
	} else if (!found) {
		item->query_last = 0;
		log_warn ("couldn't find match for query value: %s",
		          item->query_match ? item->query_match : "");
		complete_request (item, SNMP_ERR_NOSUCHNAME);


	/*
	 * Found a value but didn't match, so try next one.
	 */
	} else if (!matched) {
		log_debug ("table index %d did not match, trying next", item->query_value);
		item->query_last = 0;
		query_request (item, 0);

	/*
	 * When we have a match send off a new request, built from the original
	 * oid and the last numeric part of the query oid.
	 */
	} else {

		log_debug ("table index %d matched query value: %s",
		           item->query_value, item->query_match ? item->query_match : "");

		/* Build up the OID */
		oid = item->field_oid;
		ASSERT (oid.len < ASN_MAXOIDLEN);
		oid.subs[oid.len] = item->query_value;
		++oid.len;

		item->query_last = item->query_value;
	        item->vtype = VALUE_UNSET;

		req = snmp_engine_request (item->hostnames[item->hostindex], item->community,
		                           item->version, item->poller->interval, item->poller->timeout,
		                           SNMP_PDU_GET, &oid, field_response, item);

		item->request = req;
	}
}

static void
query_request (rb_item *item, int first)
{
	struct asn_oid oid;
	int req;

	ASSERT (item);
	ASSERT (!item->request);
	ASSERT (item->has_query);

        item->vtype = VALUE_UNSET;

	/*
	 * Build up an appropriate oid.
	 *
	 * We first try any oid that worked last time, and see if
	 * it still has the same value, to avoid doing the brute
	 * force search each time needlessly.
	 */

	/* The first time the request has been called */
	if (first)
		item->query_value = item->query_last;

	/* Try the next one in turn */
	else
		item->query_value = item->query_value + 1;

	/* Build up the OID */
	oid = item->query_oid;
	ASSERT (oid.len < ASN_MAXOIDLEN);
	oid.subs[oid.len] = item->query_value;
	++oid.len;

	/* Make the request */
	req = snmp_engine_request (item->hostnames[item->hostindex], item->community,
	                           item->version, item->poller->interval, item->poller->timeout,
	                           SNMP_PDU_GET, &oid, query_response, item);

        /* Mark item as active by this request */
	item->request = req;
}

static int
poller_timer (mstime when, void *arg)
{
	rb_poller *poll = (rb_poller*)arg;
	rb_item *item;

	/*
	 * If the previous poll has not completed, then we count it
	 * as a timeout.
	 */
	force_poll (poll, when, "timed out");

	/* Mark this poller as starting requests now */
	poll->last_request = when;

	/*
	 * Send off the next query. This needs to be done after
	 * all the timeouts above, as the above could write to RRD.
	 */
	for (item = poll->items; item; item = item->next) {
		if (item->has_query)
			query_request (item, 1);
		else
			field_request (item);
	}

	snmp_engine_flush ();

	return 1;
}

static int
prep_timer (mstime when, void* arg)
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
	if (server_timer (poll->interval, poller_timer, poll) == -1)
		log_error ("couldn't setup poller timer");

	/* Setup the next poller anywhere between 0 and 750 ms */
	next = rand () % 750;
	server_oneshot (next, prep_timer, poll->next);
	return 0;
}


void
rb_poll_engine_init (void)
{
	/* Start the preparation timers for setting up randomly */
	if (server_oneshot (100, prep_timer, g_state.polls) == -1)
		err(1, "couldn't setup timer");
}

void
rb_poll_engine_uninit (void)
{

}
