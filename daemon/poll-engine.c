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
#include <ctype.h>
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
complete_requests (rb_item *item, int code)
{
	int host;

	ASSERT (item);

	if (item->field_request)
		snmp_engine_cancel (item->field_request);
	item->field_request = 0;
	if (item->query_request)
		snmp_engine_cancel (item->query_request);
	item->query_request = 0;

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
cancel_requests (rb_item *item, mstime when, const char *reason)
{
	ASSERT (item);
	ASSERT (reason);
	ASSERT (item->field_request || item->query_request);

	log_debug ("value for field '%s': %s", item->field, reason);

	/*
	 * We note the failure has having taken place halfway between
	 * the request and the current time.
	 */
	item->last_polled = item->last_request + ((when - item->last_request) / 2);
	item->vtype = VALUE_UNSET;

	complete_requests (item, -1);
}

static void
force_poll (rb_poller *poll, mstime when, const char *reason)
{
	rb_item *item;
	int forced = 0;

	ASSERT (poll);
	ASSERT (reason);

	/* Now see if the all the requests are done */
	for (item = poll->items; item; item = item->next) {
		if (item->field_request || item->query_request) {
			cancel_requests (item, when, reason);
			forced = 1;
		}
		ASSERT (!item->field_request);
		ASSERT (!item->query_request);
	}

	if (!forced && !poll->polling)
		return;

	/* Mark any non-matched queries as unset */
	for (item = poll->items; item; item = item->next) {
		if (item->has_query && !item->query_matched)
			/*
			 * We note the failure has having taken place halfway between
			 * the request and the current time.
			 */
			item->last_polled = item->last_request + ((when - item->last_request) / 2);
			item->vtype = VALUE_UNSET;
	}

	/*
	 * We note the failure has having taken place halfway between
	 * the request and the current time.
	 */
	poll->last_polled = poll->last_request + ((when - poll->last_request) / 2);

	/* And send off our collection of values */
	rb_rrd_update (poll);

	/* This polling cycle is no longer active */
	poll->polling = 0;
}

static void
finish_poll (rb_poller *poll, mstime when)
{
	rb_item *item;

	ASSERT (poll);
	ASSERT (poll->polling);

	/* See if the all the requests are done */
	for (item = poll->items; item; item = item->next) {
		if (item->field_request || item->query_request)
			return;
	}

	/* Mark any non-matched queries as unset */
	for (item = poll->items; item; item = item->next) {
		if (item->has_query && !item->query_matched) {
			item->last_polled = when;
			item->vtype = VALUE_UNSET;
		}
	}

	/* Update the book-keeping */
	poll->last_polled = when;

	/* And send off our collection of values */
	rb_rrd_update (poll);

	/* This polling cycle is no longer active */
	poll->polling = 0;
}

static int
parse_string_value (struct snmp_value *value, rb_item *item)
{
	char buf[256];
	char *t, *b;

	ASSERT (value);
	ASSERT (value->syntax == SNMP_SYNTAX_OCTETSTRING);
	ASSERT (item);

	if(value->v.octetstring.len >= sizeof(buf))
		return 0;

	memset(buf, 0, sizeof(buf));
	strncpy(buf, (char*)value->v.octetstring.octets, value->v.octetstring.len);

	/* Remove leading spaces */
	b = buf;
	while(isspace(*b))
		++b;

	/* Cannot parse empty strings */
	if(!*b)
		return 0;

	/* Try to parse the string into an integer */
	item->v.i_value = strtoll(b, &t, 10);
	if(!*t || isspace(*t)) {
		item->vtype = VALUE_REAL;
		return 1;
	}

	/* Try to parse the string into a floating point */
	item->v.f_value = strtod(b, &t);
	if(!*t || isspace(*t)) {
		item->vtype = VALUE_FLOAT;
		return 1;
	}

	return 0;
}

static void
field_response (int request, int code, struct snmp_value *value, void *arg)
{
	rb_item *item = arg;
	mstime when;
	char asnbuf[ASN_OIDSTRLEN];

	ASSERT (request == item->field_request);

	/* Note when the response for this item arrived */
	when = server_get_time ();
	item->last_polled = when;

	/* Mark this item as done */
	item->field_request = 0;

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
		case SNMP_SYNTAX_COUNTER:       /* FALLTHROUGH */
		case SNMP_SYNTAX_GAUGE:         /* FALLTHROUGH */
		case SNMP_SYNTAX_TIMETICKS:
			item->v.i_value = value->v.uint32;
			item->vtype = VALUE_REAL;
			break;
		case SNMP_SYNTAX_COUNTER64:
			item->v.i_value = value->v.counter64;
			item->vtype = VALUE_REAL;
			break;
		case SNMP_SYNTAX_OCTETSTRING:
			if (parse_string_value(value, item))
				break;
			/* FALLTHROUGH */
		case SNMP_SYNTAX_OID: 		/* FALLTHROUGH */
		case SNMP_SYNTAX_IPADDRESS:	/* FALLTHROUGH */
		case SNMP_SYNTAX_NOSUCHOBJECT:	/* FALLTHROUGH */
		case SNMP_SYNTAX_NOSUCHINSTANCE:/* FALLTHROUGH */
		case SNMP_SYNTAX_ENDOFMIBVIEW:	/* FALLTHROUGH */
		default:
			log_warnx("snmp server %s: oid %s: field %s: response %s(%u)",
			    item->hostnames[item->hostindex],
			    asn_oid2str_r(&item->field_oid, asnbuf),
			    item->field,
			    snmp_get_syntaxmsg(value->syntax),
			    value->syntax);
			break;
		};

		if (item->vtype == VALUE_REAL)
			log_debug ("got value for field '%s': %lld",
			           item->field, item->v.i_value);
		else if (item->vtype == VALUE_FLOAT)
			log_debug ("got value for field '%s': %.4lf",
			           item->field, item->v.f_value);
		else
			log_debug ("got value for field '%s': U",
			           item->field);
	}

	complete_requests (item, code);

	/* If the entire poll is done, then complete it */
	finish_poll (item->poller, when);
}

static void
field_request (rb_item *item)
{
	int req;

	ASSERT (item);
	ASSERT (!item->field_request);

	item->vtype = VALUE_UNSET;

	req = snmp_engine_request (item->hostnames[item->hostindex], item->portnum, item->community,
	                           item->version, item->poller->interval, item->poller->timeout,
	                           SNMP_PDU_GET, &item->field_oid, field_response, item);
	item->field_request = req;
}

/* Forward declaration */
static void query_search_request (rb_item *item);

static void
query_value_request (rb_item *item, asn_subid_t subid)
{
	struct asn_oid oid;
	int req;

	ASSERT (item);
	ASSERT (item->has_query);
	ASSERT (!item->query_request);
	ASSERT (!item->field_request);

	item->vtype = VALUE_UNSET;

	/* OID for the actual value */
	oid = item->field_oid;
	ASSERT (oid.len < ASN_MAXOIDLEN);
	oid.subs[oid.len] = subid;
	++oid.len;

	log_debug ("query requesting value for table index: %u", subid);

	req = snmp_engine_request (item->hostnames[item->hostindex], item->portnum, item->community,
	                           item->version, item->poller->interval, item->poller->timeout,
	                           SNMP_PDU_GET, &oid, field_response, item);

	/* Value retrieval is active */
	item->field_request = req;
}

static void
query_next_response (int request, int code, struct snmp_value *value, void *arg)
{
	rb_item *item = arg;
	asn_subid_t subid;
	int matched;

	/*
	 * Called when we get the next OID in a table
	 */

	ASSERT (request == item->query_request);
	ASSERT (!item->field_request);

	/* Mark this item as done */
	item->query_request = 0;

	if (code == SNMP_ERR_NOERROR) {
		ASSERT (value);

		/* Convert these result codes into 'not found' */
		switch (value->syntax) {
		case SNMP_SYNTAX_NOSUCHOBJECT:
		case SNMP_SYNTAX_NOSUCHINSTANCE:
		case SNMP_SYNTAX_ENDOFMIBVIEW:
			code = SNMP_ERR_NOSUCHNAME;
			break;

		/*
		 * Make sure that we haven't gone past the end. For it to
		 * be in the table it must be exactly one longer (the table index)
		 * and otherwise identical.
		 */
		default:
			if (item->query_oid.len + 1 != value->var.len ||
			    !asn_is_suboid (&item->query_oid, &value->var))
				code = SNMP_ERR_NOSUCHNAME;
			break;
		};
	}

	if (code == SNMP_ERR_NOSUCHNAME)
		log_debug ("query couldn't find table index that matches: %s",
		           item->query_match ? item->query_match : "[null]");


	/* Problems communicating with the server, or not found */
	if (code != SNMP_ERR_NOERROR) {
		memset (&item->query_last, 0, sizeof (item->query_last));
		complete_requests (item, code);
		return;
	}

	/* Save away the last OID we've seen */
	item->query_last = value->var;
	item->query_searched = 1;

	ASSERT (value);

	/* Match the query value received */
	if (item->query_match)
		matched = snmp_engine_match (value, item->query_match);

	/* When query match is null, anything matches */
	else
		matched = 1;

	item->query_matched = matched;
	item->vtype = VALUE_UNSET;

	if (matched) {
		/* Do a query for the field value with this sub id */
		subid = value->var.subs[value->var.len - 1];
		query_value_request (item, subid);
	} else {
		/* Look for the next table index */
		query_search_request (item);
	}
}

static void
query_search_request (rb_item *item)
{
	struct asn_oid *oid;
	int req;

	ASSERT (item);
	ASSERT (item->has_query);
	ASSERT (!item->query_request);
	ASSERT (!item->field_request);

	item->query_matched = 0;
	item->vtype = VALUE_UNSET;

	/* Start with the OID without any table index */
	if (!item->query_searched) {
		oid = &item->query_oid;
		memset (&item->query_last, 0, sizeof (item->query_last));
		log_debug ("query looking for first table index");

	/* Go for the next one in the search */
	} else {
		ASSERT (item->query_last.len > 0);
		oid = &item->query_last;
		log_debug ("query looking for next table index");
	}

	req = snmp_engine_request (item->hostnames[item->hostindex], item->portnum, item->community,
	                           item->version, item->poller->interval, item->poller->timeout,
	                           SNMP_PDU_GETNEXT, oid, query_next_response, item);

	item->query_request = req;
}

static void
query_match_response (int request, int code, struct snmp_value *value, void *arg)
{
	rb_item *item = arg;
	int matched;

	/*
	 * Callback when SNMP request in query_request() completes.
	 *
	 * We receive a value back from the server when querying the table match OID,
	 * whenever we queried it directly (without the search).
	 */

	ASSERT (request == item->query_request);

	/* Problems communicating with the server? */
	if (code != SNMP_ERR_NOERROR && code != SNMP_ERR_NOSUCHNAME) {
		complete_requests (item, code);
		return;
	}

	/*
	 * Mark this item as done after the possible call to complete_requests
	 * otherwise complete_requests won't free everything.
	 */
	item->query_request = 0;

	matched = 0;

	if (code == SNMP_ERR_NOERROR) {
		ASSERT (value);

		/* These all signify 'not found' in our book */
		switch (value->syntax) {
		case SNMP_SYNTAX_NOSUCHOBJECT:
		case SNMP_SYNTAX_NOSUCHINSTANCE:
		case SNMP_SYNTAX_ENDOFMIBVIEW:
			break;

		/* See if we have a match */
		default:
			if (item->query_match)
				matched = snmp_engine_match (value, item->query_match);

			/* When query match is null, anything matches */
			else
				matched = 1;
			break;
		};
	}

	item->query_matched = matched;
	if (matched)
		return;

	log_debug ("query previous index did not match: %s",
	           item->query_match ? item->query_match : "[null]");

	/*
	 * When it doesn't match cancel any pending value request, and
	 * start a search for a match.
	 */
	if (item->field_request)
		snmp_engine_cancel (item->field_request);
	item->field_request = 0;
	query_search_request (item);
}

static void
query_pair_request (rb_item *item, asn_subid_t subid)
{
	struct asn_oid oid;
	int req;

	ASSERT (item);
	ASSERT (item->has_query);
	ASSERT (!item->query_request);
	ASSERT (!item->field_request);

	log_debug ("query requesting match and value pair for index: %u", subid);

	item->vtype = VALUE_UNSET;
	item->query_matched = 0;

	/* OID for the value to match */
	oid = item->query_oid;
	ASSERT (oid.len < ASN_MAXOIDLEN);
	oid.subs[oid.len] = subid;
	++oid.len;

	req = snmp_engine_request (item->hostnames[item->hostindex], item->portnum, item->community,
	                           item->version, item->poller->interval, item->poller->timeout,
	                           SNMP_PDU_GET, &oid, query_match_response, item);

	/* Query is active */
	item->query_request = req;

	/* OID for the actual value */
	oid = item->field_oid;
	ASSERT (oid.len < ASN_MAXOIDLEN);
	oid.subs[oid.len] = subid;
	++oid.len;

	req = snmp_engine_request (item->hostnames[item->hostindex], item->portnum, item->community,
	                           item->version, item->poller->interval, item->poller->timeout,
	                           SNMP_PDU_GET, &oid, field_response, item);

	/* Value retrieval is active */
	item->field_request = req;
}

static void
query_request (rb_item *item)
{
	ASSERT (item);
	ASSERT (!item->query_request);
	ASSERT (!item->field_request);

	item->query_searched = 0;
	item->query_matched = 0;
	item->vtype = VALUE_UNSET;

	if (item->query_last.len) {

		/*
		 * If we've done this query before, then we know the last matching table
		 * index. We build a two part request that gets the match value for the
		 * table index it was last seen on, and the actual value that we want.
		 *
		 * Doing this in one request is more efficient, then we check if the
		 * match value matches the query in the response.
		 */
		query_pair_request (item, item->query_last.subs[item->query_last.len - 1]);

	} else {

		/*
		 * We don't have a last matching table index, so start the search.
		 * For indexes. We'll then query each of those indexes with the two
		 * part request, as above.
		 */
		query_search_request (item);
	}
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
	ASSERT (!poll->polling);
	poll->polling = 1;

	/*
	 * Send off the next query. This needs to be done after
	 * all the timeouts above, as the above could write to RRD.
	 */
	for (item = poll->items; item; item = item->next) {
		item->last_request = when;
		if (item->has_query)
			query_request (item);
		else
			field_request (item);
	}

	snmp_engine_flush ();

	return 1;
}

static int
prep_timer (mstime when, void* arg)
{
	rb_poller* poll;

	poll = (rb_poller*)arg;
	if (server_timer (poll->interval, poller_timer, poll) == -1)
		log_error ("couldn't setup poller timer");

	/* Run the poll the first time */
	poller_timer (when, poll);

	return 0;
}


void
rb_poll_engine_init (void)
{
	/*
	 * Randomly start all timers with a small random offset of between
	 * 0-interval time. This spreads the polls out over a few seconds.
	 */
	rb_poller * poll;
	int rand_delay;

	for (poll = g_state.polls; poll != NULL; poll = poll->next) {
		rand_delay = rand() % poll->interval;
		if (server_oneshot(rand_delay, prep_timer, poll) == -1)
		    err(1, "couldn't setup timer");
	}
}

void
rb_poll_engine_uninit (void)
{
	rb_poller * poll = g_state.polls;
	rb_item *item;
	mstime when;

	if (poll != NULL) {
		/* Now see if the all the requests are done */
		when = server_get_time ();
		for (item = poll->items; item; item = item->next) {
			if (item->field_request || item->query_request) {
				cancel_requests (item, when, "shutdown");
			}
			ASSERT (!item->field_request);
			ASSERT (!item->query_request);
		}
	}
}
