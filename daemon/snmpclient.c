/*
 * Copyright (c) 2004-2005
 *	Hartmut Brandt.
 *	All rights reserved.
 * Copyright (c) 2001-2003
 *	Fraunhofer Institute for Open Communication Systems (FhG Fokus).
 *	All rights reserved.
 *
 * Author: Harti Brandt <harti@freebsd.org>
 *         Kendy Kutzner
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Begemot: bsnmp/lib/snmpclient.c,v 1.31 2005/05/23 11:10:13 brandt_h Exp $
 *
 * Support functions for SNMP clients.
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <limits.h>
#ifdef HAVE_ERR_H
#include <err.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmpclient.h"
#include "snmppriv.h"

/* ---------------------------------------------------------------------------- */

#define LIST_EMPTY(head)        ((head)->lh_first == NULL)
#define LIST_FIRST(head)        ((head)->lh_first)
#define LIST_NEXT(elm, field)   ((elm)->field.le_next)
#define LIST_FOREACH(var, head, field)                                  \
        for ((var) = LIST_FIRST((head));                                \
            (var);                                                      \
            (var) = LIST_NEXT((var), field))


/* ---------------------------------------------------------------------------- */

/* global context */
struct snmp_client snmp_client;

/* List of all outstanding requests */
struct sent_pdu {
	int		reqid;
	struct snmp_pdu	*pdu;
	struct timeval	time;
	u_int		retrycount;
	snmp_send_cb_f	callback;
	void		*arg;
	void		*timeout_id;
	LIST_ENTRY(sent_pdu) entries;
};
LIST_HEAD(sent_pdu_list, sent_pdu);

static struct sent_pdu_list sent_pdus;

/*
 * Set the error string
 */
static void
seterr(struct snmp_client *sc, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(sc->error, sizeof(sc->error), fmt, ap);
	va_end(ap);
}

/*
 * Initialize a client structure
 */
void
snmp_client_init(struct snmp_client *c)
{
	memset(c, 0, sizeof(*c));

	c->version = SNMP_V2c;
	c->trans = SNMP_TRANS_UDP;
	c->chost = NULL;
	c->cport = NULL;

	strcpy(c->read_community, "public");
	strcpy(c->write_community, "private");

	c->timeout.tv_sec = 3;
	c->timeout.tv_usec = 0;
	c->retries = 3;
	c->dump_pdus = 0;
	c->txbuflen = c->rxbuflen = 10000;

	c->fd = -1;

	c->max_reqid = INT32_MAX;
	c->min_reqid = 0;
	c->next_reqid = 0;
}


/*
 * Open UDP client socket
 */
static int
open_client_udp(const char *host, const char *port)
{
	int error;
	char *ptr;
	struct addrinfo hints, *res0, *res;

	/* copy host- and portname */
	if (snmp_client.chost == NULL) {
		if ((snmp_client.chost = malloc(1 + sizeof(DEFAULT_HOST)))
		    == NULL) {
			seterr(&snmp_client, "%s", strerror(errno));
			return (-1);
		}
		strcpy(snmp_client.chost, DEFAULT_HOST);
	}
	if (host != NULL) {
		if ((ptr = malloc(1 + strlen(host))) == NULL) {
			seterr(&snmp_client, "%s", strerror(errno));
			return (-1);
		}
		free(snmp_client.chost);
		snmp_client.chost = ptr;
		strcpy(snmp_client.chost, host);
	}
	if (snmp_client.cport == NULL) {
		if ((snmp_client.cport = malloc(1 + sizeof(DEFAULT_PORT)))
		    == NULL) {
			seterr(&snmp_client, "%s", strerror(errno));
			return (-1);
		}
		strcpy(snmp_client.cport, DEFAULT_PORT);
	}
	if (port != NULL) {
		if ((ptr = malloc(1 + strlen(port))) == NULL) {
			seterr(&snmp_client, "%s", strerror(errno));
			return (-1);
		}
		free(snmp_client.cport);
		snmp_client.cport = ptr;
		strcpy(snmp_client.cport, port);
	}

	/* open connection */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	error = getaddrinfo(snmp_client.chost, snmp_client.cport, &hints, &res0);
	if (error != 0) {
		seterr(&snmp_client, "%s: %s", snmp_client.chost,
		    gai_strerror(error));
		return (-1);
	}
	res = res0;
	for (;;) {
		if ((snmp_client.fd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol)) == -1) {
			if ((res = res->ai_next) == NULL) {
				seterr(&snmp_client, "%s", strerror(errno));
				freeaddrinfo(res0);
				return (-1);
			}
		} else if (connect(snmp_client.fd, res->ai_addr,
		    res->ai_addrlen) == -1) {
			if ((res = res->ai_next) == NULL) {
				seterr(&snmp_client, "%s", strerror(errno));
				freeaddrinfo(res0);
				return (-1);
			}
		} else
			break;
	}
	freeaddrinfo(res0);
	return (0);
}

/*
 * SNMP_OPEN
 */
int
snmp_open(const char *host, const char *port, const char *readcomm,
    const char *writecomm)
{
	struct timeval tout;

	/* still open ? */
	if (snmp_client.fd != -1) {
		errno = EBUSY;
		seterr(&snmp_client, "%s", strerror(errno));
		return (-1);
	}

	/* copy community strings */
	if (readcomm != NULL) {
		strncpy(snmp_client.read_community, readcomm,
		    sizeof(snmp_client.read_community));
        snmp_client.read_community[sizeof(snmp_client.read_community) - 1] = 0;
    }
	if (writecomm != NULL) {
		strncpy(snmp_client.write_community, writecomm,
		    sizeof(snmp_client.write_community));
        snmp_client.write_community[sizeof(snmp_client.write_community) - 1] = 0;
    }

	switch (snmp_client.trans) {

	  case SNMP_TRANS_UDP:
		if (open_client_udp(host, port))
			return (-1);
		break;

	  default:
		seterr(&snmp_client, "bad transport mapping");
		return (-1);
	}
	tout.tv_sec = 0;
	tout.tv_usec = 0;
	if (setsockopt(snmp_client.fd, SOL_SOCKET, SO_SNDTIMEO,
	    &tout, sizeof(struct timeval)) == -1) {
		seterr(&snmp_client, "%s", strerror(errno));
		(void)close(snmp_client.fd);
		snmp_client.fd = -1;
		if (snmp_client.local_path[0] != '\0')
			(void)remove(snmp_client.local_path);
		return (-1);
	}

	/* initialize list */
	LIST_INIT(&sent_pdus);

	return (0);
}


/*
 * SNMP_CLOSE
 *
 * closes connection to snmp server
 * - function cannot fail
 * - clears connection
 * - clears list of sent pdus
 *
 * input:
 *  void
 * return:
 *  void
 */
void
snmp_close(void)
{
	struct sent_pdu *p1;

	if (snmp_client.fd != -1) {
		(void)close(snmp_client.fd);
		snmp_client.fd = -1;
		if (snmp_client.local_path[0] != '\0')
			(void)remove(snmp_client.local_path);
	}
	while(!LIST_EMPTY(&sent_pdus)){
		p1 = LIST_FIRST(&sent_pdus);
		if (p1->timeout_id != NULL)
			snmp_client.timeout_stop(p1->timeout_id);
		LIST_REMOVE(p1, entries);
		free(p1);
	}
	free(snmp_client.chost);
	free(snmp_client.cport);
}

/*
 * initialize a snmp_pdu structure
 */
void
snmp_pdu_create(struct snmp_pdu *pdu, u_int op)
{
	memset(pdu,0,sizeof(struct snmp_pdu));
	if (op == SNMP_PDU_SET)
		strncpy(pdu->community, snmp_client.write_community,
		    sizeof(pdu->community));
    else
		strncpy(pdu->community, snmp_client.read_community,
		    sizeof(pdu->community));
    pdu->community[sizeof(pdu->community) - 1] = 0;


	pdu->type = op;
	pdu->version = snmp_client.version;
	pdu->error_status = 0;
	pdu->error_index = 0;
	pdu->nbindings = 0;
}

/* add pairs of (struct asn_oid, enum snmp_syntax) to an existing pdu */
/* added 10/04/02 by kek: check for MAX_BINDINGS */
int
snmp_add_binding(struct snmp_v1_pdu *pdu, ...)
{
	va_list ap;
	const struct asn_oid *oid;
	u_int ret;

	va_start(ap, pdu);

	ret = pdu->nbindings;
	while ((oid = va_arg(ap, const struct asn_oid *)) != NULL) {
		if (pdu->nbindings >= SNMP_MAX_BINDINGS){
			va_end(ap);
			return (-1);
		}
		pdu->bindings[pdu->nbindings].var = *oid;
		pdu->bindings[pdu->nbindings].syntax =
		    va_arg(ap, enum snmp_syntax);
		pdu->nbindings++;
	}
	va_end(ap);
	return (ret);
}


static int32_t
snmp_next_reqid(struct snmp_client * c)
{
	int32_t i;

	i = c->next_reqid;
	if (c->next_reqid >= c->max_reqid)
		c->next_reqid = c->min_reqid;
	else
		c->next_reqid++;
	return (i);
}

/*
 * Send request and return request id.
 */
static int32_t
snmp_send_packet(struct snmp_pdu * pdu)
{
        u_char *buf;
        struct asn_buf b;
        ssize_t ret;

	if ((buf = malloc(snmp_client.txbuflen)) == NULL) {
		seterr(&snmp_client, "%s", strerror(errno));
		return (-1);
	}

        pdu->request_id = snmp_next_reqid(&snmp_client);

        b.asn_ptr = buf;
        b.asn_len = snmp_client.txbuflen;
        if (snmp_pdu_encode(pdu, &b)) {
		seterr(&snmp_client, "%s", strerror(errno));
		free(buf);
		return (-1);
	}

        if (snmp_client.dump_pdus)
                snmp_pdu_dump(pdu);

        if ((ret = send(snmp_client.fd, buf, b.asn_ptr - buf, 0)) == -1) {
		seterr(&snmp_client, "%s", strerror(errno));
		free(buf);
                return (-1);
	}
	free(buf);

	return pdu->request_id;
}

/*
 * to be called when a snmp request timed out
 */
static void
snmp_timeout(void * listentry_ptr)
{
	struct sent_pdu *listentry = listentry_ptr;

#if 0
	warnx("snmp request %i timed out, attempt (%i/%i)",
	    listentry->reqid, listentry->retrycount, snmp_client.retries);
#endif

	listentry->retrycount++;
	if (listentry->retrycount > snmp_client.retries) {
		/* there is no answer at all */
		LIST_REMOVE(listentry, entries);
		listentry->callback(listentry->pdu, NULL, listentry->arg);
		free(listentry);
	} else {
		/* try again */
		/* new request with new request ID */
		listentry->reqid = snmp_send_packet(listentry->pdu);
		listentry->timeout_id =
		    snmp_client.timeout_start(&snmp_client.timeout,
		    snmp_timeout, listentry);
	}
}

int32_t
snmp_pdu_send(struct snmp_pdu *pdu, snmp_send_cb_f func, void *arg)
{
	struct sent_pdu *listentry;
	int32_t id;

	if ((listentry = malloc(sizeof(struct sent_pdu))) == NULL) {
		seterr(&snmp_client, "%s", strerror(errno));
		return (-1);
	}

	/* here we really send */
	if ((id = snmp_send_packet(pdu)) == -1) {
		free(listentry);
		return (-1);
	}

	/* add entry to list of sent PDUs */
	listentry->pdu = pdu;
	if (gettimeofday(&listentry->time, NULL) == -1)
		warn("gettimeofday() failed");

	listentry->reqid = pdu->request_id;
	listentry->callback = func;
	listentry->arg = arg;
	listentry->retrycount=1;
	listentry->timeout_id =
	    snmp_client.timeout_start(&snmp_client.timeout, snmp_timeout,
	    listentry);

	LIST_INSERT_HEAD(&sent_pdus, listentry, entries);

	return (id);
}

/*
 * Receive an SNMP packet.
 *
 * tv controls how we wait for a packet: if tv is a NULL pointer,
 * the receive blocks forever, if tv points to a structure with all
 * members 0 the socket is polled, in all other cases tv specifies the
 * maximum time to wait for a packet.
 *
 * Return:
 *	-1 on errors
 *	0 on timeout
 *	+1 if packet received
 */
static int
snmp_receive_packet(struct snmp_pdu *pdu, struct timeval *tv)
{
	int dopoll, setpoll;
	int flags;
	int saved_errno;
	u_char *buf;
	int ret;
	struct asn_buf abuf;
	int32_t ip;
#ifdef bsdi
	int optlen;
#else
	socklen_t optlen;
#endif

	if ((buf = malloc(snmp_client.rxbuflen)) == NULL) {
		seterr(&snmp_client, "%s", strerror(errno));
		return (-1);
	}
	dopoll = setpoll = 0;
	flags = 0;
	if (tv != NULL) {
		/* poll or timeout */
		if (tv->tv_sec != 0 || tv->tv_usec != 0) {
			/* wait with timeout */
			if (setsockopt(snmp_client.fd, SOL_SOCKET, SO_RCVTIMEO,
			    tv, sizeof(*tv)) == -1) {
				seterr(&snmp_client, "setsockopt: %s",
				    strerror(errno));
				free(buf);
				return (-1);
			}
			optlen = sizeof(*tv);
			if (getsockopt(snmp_client.fd, SOL_SOCKET, SO_RCVTIMEO,
			    tv, &optlen) == -1) {
				seterr(&snmp_client, "getsockopt: %s",
				    strerror(errno));
				free(buf);
				return (-1);
			}
			/* at this point tv_sec and tv_usec may appear
			 * as 0. This happens for timeouts lesser than
			 * the clock granularity. The kernel rounds these to
			 * 0 and this would result in a blocking receive.
			 * Instead of an else we check tv_sec and tv_usec
			 * again below and if this rounding happens,
			 * switch to a polling receive. */
		}
		if (tv->tv_sec == 0 && tv->tv_usec == 0) {
			/* poll */
			dopoll = 1;
			if ((flags = fcntl(snmp_client.fd, F_GETFL, 0)) == -1) {
				seterr(&snmp_client, "fcntl: %s",
				    strerror(errno));
				free(buf);
				return (-1);
			}
			if (!(flags & O_NONBLOCK)) {
				setpoll = 1;
				flags |= O_NONBLOCK;
				if (fcntl(snmp_client.fd, F_SETFL, flags) == -1) {
					seterr(&snmp_client, "fcntl: %s",
					    strerror(errno));
					free(buf);
					return (-1);
				}
			}
		}
	}
	ret = recv(snmp_client.fd, buf, snmp_client.rxbuflen, 0);
	saved_errno = errno;
	if (tv != NULL) {
		if (dopoll) {
			if (setpoll) {
				flags &= ~O_NONBLOCK;
				(void)fcntl(snmp_client.fd, F_SETFL, flags);
			}
		} else {
			tv->tv_sec = 0;
			tv->tv_usec = 0;
			(void)setsockopt(snmp_client.fd, SOL_SOCKET, SO_RCVTIMEO,
			    tv, sizeof(*tv));
		}
	}
	if (ret == -1) {
		free(buf);
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return (0);
		seterr(&snmp_client, "recv: %s", strerror(saved_errno));
		return (-1);
	}
	if (ret == 0) {
		/* this happens when we have a streaming socket and the
		 * remote side has closed it */
		free(buf);
		seterr(&snmp_client, "recv: socket closed by peer");
		errno = EPIPE;
		return (-1);
	}

	abuf.asn_ptr = buf;
	abuf.asn_len = ret;

	if (SNMP_CODE_OK != (ret = snmp_pdu_decode(&abuf, pdu, &ip))) {
		seterr(&snmp_client, "snmp_decode_pdu: failed %d", ret);
		free(buf);
		return (-1);
	}
	free(buf);
	if (snmp_client.dump_pdus)
		snmp_pdu_dump(pdu);

	return (+1);
}

static int
snmp_deliver_packet(struct snmp_pdu * resp)
{
	struct sent_pdu *listentry;

	if (resp->type != SNMP_PDU_RESPONSE) {
		warn("ignoring snmp pdu %u", resp->type);
		return (-1);
	}

	LIST_FOREACH(listentry, &sent_pdus, entries)
		if (listentry->reqid == resp->request_id)
			break;
	if (listentry == NULL)
		return (-1);

	LIST_REMOVE(listentry, entries);
	listentry->callback(listentry->pdu, resp, listentry->arg);

	snmp_client.timeout_stop(listentry->timeout_id);

	free(listentry);
	return (0);
}

int
snmp_receive(int blocking)
{
	int ret;

	struct timeval tv;
	struct snmp_pdu * resp;

	memset(&tv, 0, sizeof(tv));

	resp = malloc(sizeof(struct snmp_pdu));
	if (resp == NULL) {
		seterr(&snmp_client, "no memory for returning PDU");
		return (-1) ;
	}

	if ((ret = snmp_receive_packet(resp, blocking ? NULL : &tv)) <= 0) {
		free(resp);
		return (ret);
	}
	ret = snmp_deliver_packet(resp);
	snmp_pdu_free(resp);
	free(resp);
	return (ret);
}


/*
 * Check a GETNEXT response. Here we have three possible outcomes: -1 an
 * unexpected error happened. +1 response is ok and is within the table 0
 * response is ok, but is behind the table or error is NOSUCHNAME. The req
 * should point to a template PDU which contains the base OIDs and the
 * syntaxes. This is really only useful to sweep non-sparse tables.
 */
static int
ok_getnext(const struct snmp_pdu * req, const struct snmp_pdu * resp)
{
	u_int i;

	if (resp->version != req->version) {
		warnx("SNMP GETNEXT: response has wrong version");
		return (-1);
	}

	if (resp->error_status == SNMP_ERR_NOSUCHNAME)
		return (0);

	if (resp->error_status != SNMP_ERR_NOERROR) {
		warnx("SNMP GETNEXT: error %d", resp->error_status);
		return (-1);
	}
	if (resp->nbindings != req->nbindings) {
		warnx("SNMP GETNEXT: bad number of bindings in response");
		return (-1);
	}
	for (i = 0; i < req->nbindings; i++) {
		if (!asn_is_suboid(&req->bindings[i].var,
		    &resp->bindings[i].var)) {
			if (i != 0)
				warnx("SNMP GETNEXT: inconsistent table "
				      "response");
			return (0);
		}
		if (resp->version != SNMP_V1 &&
		    resp->bindings[i].syntax == SNMP_SYNTAX_ENDOFMIBVIEW)
			return (0);

		if (resp->bindings[i].syntax != req->bindings[i].syntax) {
			warnx("SNMP GETNEXT: bad syntax in response");
			return (0);
		}
	}
	return (1);
}

/*
 * Check a GET response. Here we have three possible outcomes: -1 an
 * unexpected error happened. +1 response is ok. 0 NOSUCHNAME The req should
 * point to a template PDU which contains the OIDs and the syntaxes. This
 * is only useful for SNMPv1 or single object GETS.
 */
static int
ok_get(const struct snmp_pdu * req, const struct snmp_pdu * resp)
{
	u_int i;

	if (resp->version != req->version) {
		warnx("SNMP GET: response has wrong version");
		return (-1);
	}

	if (resp->error_status == SNMP_ERR_NOSUCHNAME)
		return (0);

	if (resp->error_status != SNMP_ERR_NOERROR) {
		warnx("SNMP GET: error %d", resp->error_status);
		return (-1);
	}

	if (resp->nbindings != req->nbindings) {
		warnx("SNMP GET: bad number of bindings in response");
		return (-1);
	}
	for (i = 0; i < req->nbindings; i++) {
		if (asn_compare_oid(&req->bindings[i].var,
		    &resp->bindings[i].var) != 0) {
			warnx("SNMP GET: bad OID in response");
			return (-1);
		}
		if (snmp_client.version != SNMP_V1 &&
		    (resp->bindings[i].syntax == SNMP_SYNTAX_NOSUCHOBJECT ||
		    resp->bindings[i].syntax == SNMP_SYNTAX_NOSUCHINSTANCE))
			return (0);
		if (resp->bindings[i].syntax != req->bindings[i].syntax) {
			warnx("SNMP GET: bad syntax in response");
			return (-1);
		}
	}
	return (1);
}

/*
 * Check the reponse to a SET PDU. We check: - the error status must be 0 -
 * the number of bindings must be equal in response and request - the
 * syntaxes must be the same in response and request - the OIDs must be the
 * same in response and request
 */
static int
ok_set(const struct snmp_pdu * req, const struct snmp_pdu * resp)
{
	u_int i;

	if (resp->version != req->version) {
		warnx("SNMP SET: response has wrong version");
		return (-1);
	}

	if (resp->error_status == SNMP_ERR_NOSUCHNAME) {
		warnx("SNMP SET: error %d", resp->error_status);
		return (0);
	}
	if (resp->error_status != SNMP_ERR_NOERROR) {
		warnx("SNMP SET: error %d", resp->error_status);
		return (-1);
	}

	if (resp->nbindings != req->nbindings) {
		warnx("SNMP SET: bad number of bindings in response");
		return (-1);
	}
	for (i = 0; i < req->nbindings; i++) {
		if (asn_compare_oid(&req->bindings[i].var,
		    &resp->bindings[i].var) != 0) {
			warnx("SNMP SET: wrong OID in response to SET");
			return (-1);
		}
		if (resp->bindings[i].syntax != req->bindings[i].syntax) {
			warnx("SNMP SET: bad syntax in response");
			return (-1);
		}
	}
	return (1);
}

/*
 * Simple checks for response PDUs against request PDUs. Return values: 1=ok,
 * 0=nosuchname or similar, -1=failure, -2=no response at all
 */
int
snmp_pdu_check(const struct snmp_pdu *req,
    const struct snmp_pdu *resp)
{
	if (resp == NULL)
		return (-2);

	switch (req->type) {

	  case SNMP_PDU_GET:
		return (ok_get(req, resp));

	  case SNMP_PDU_SET:
		return (ok_set(req, resp));

	  case SNMP_PDU_GETNEXT:
		return (ok_getnext(req, resp));

	}
	errx(1, "%s: bad pdu type %i", __func__, req->type);
}

int
snmp_dialog(struct snmp_v1_pdu *req, struct snmp_v1_pdu *resp)
{
        u_int i;
        int32_t reqid;
	int ret;
        struct timeval tv = snmp_client.timeout;
	struct timeval end;
	struct snmp_pdu pdu;

	/*
	 * Make a copy of the request and replace the syntaxes by NULL
	 * if this is a GET,GETNEXT or GETBULK.
	 */
	pdu = *req;
	if (pdu.type == SNMP_PDU_GET || pdu.type == SNMP_PDU_GETNEXT ||
	    pdu.type == SNMP_PDU_GETBULK) {
		for (i = 0; i < pdu.nbindings; i++)
			pdu.bindings[i].syntax = SNMP_SYNTAX_NULL;
	}

        for (i = 0; i <= snmp_client.retries; i++) {
		(void)gettimeofday(&end, NULL);
		timeradd(&end, &snmp_client.timeout, &end);
                if ((reqid = snmp_send_packet(&pdu)) == -1)
			return (-1);
		for (;;) {
			(void)gettimeofday(&tv, NULL);
			if (timercmp(&end, &tv, <=))
				break;
			timersub(&end, &tv, &tv);
			if ((ret = snmp_receive_packet(resp, &tv)) == 0)
				/* timeout */
				break;

			if (ret > 0) {
				if (reqid == resp->request_id)
					return (0);
				/* not for us */
				(void)snmp_deliver_packet(resp);
			}
			if (ret < 0 && errno == EPIPE)
				/* stream closed */
				return (-1);
		}
        }
	errno = ETIMEDOUT;
	seterr(&snmp_client, "retry count exceeded");
        return (-1);
}

/*
 * parse a server specification
 *
 * [trans::][community@][server][:port]
 */
int
snmp_parse_server(struct snmp_client *sc, const char *str)
{
	const char *p, *s = str;

	/* look for a double colon */
	for (p = s; *p != '\0'; p++) {
		if (*p == '\\' && p[1] != '\0') {
			p++;
			continue;
		}
		if (*p == ':' && p[1] == ':')
			break;
	}
	if (*p != '\0') {
		if (p > s) {
			if (p - s == 3 && strncmp(s, "udp", 3) == 0)
				sc->trans = SNMP_TRANS_UDP;
			else if (p - s == 6 && strncmp(s, "stream", 6) == 0)
				sc->trans = SNMP_TRANS_LOC_STREAM;
			else if (p - s == 5 && strncmp(s, "dgram", 5) == 0)
				sc->trans = SNMP_TRANS_LOC_DGRAM;
			else {
				seterr(sc, "unknown SNMP transport '%.*s'",
				    (int)(p - s), s);
				return (-1);
			}
		}
		s = p + 2;
	}

	/* look for a @ */
	for (p = s; *p != '\0'; p++) {
		if (*p == '\\' && p[1] != '\0') {
			p++;
			continue;
		}
		if (*p == '@')
			break;
	}

	if (*p != '\0') {
		if (p - s > SNMP_COMMUNITY_MAXLEN) {
			seterr(sc, "community string too long");
			return (-1);
		}
		strncpy(sc->read_community, s, p - s);
		sc->read_community[p - s] = '\0';
		strncpy(sc->write_community, s, p - s);
		sc->write_community[p - s] = '\0';
		s = p + 1;
	}

	/* look for a colon */
	for (p = s; *p != '\0'; p++) {
		if (*p == '\\' && p[1] != '\0') {
			p++;
			continue;
		}
		if (*p == ':')
			break;
	}

	if (*p == ':') {
		if (p > s) {
			/* host:port */
			free(sc->chost);
			if ((sc->chost = malloc(p - s + 1)) == NULL) {
				seterr(sc, "%s", strerror(errno));
				return (-1);
			}
			strncpy(sc->chost, s, p - s);
			sc->chost[p - s] = '\0';
		}
		/* port */
		free(sc->cport);
		if ((sc->cport = malloc(strlen(p + 1) + 1)) == NULL) {
			seterr(sc, "%s", strerror(errno));
			return (-1);
		}
		strcpy(sc->cport, p + 1);

	} else if (p > s) {
		/* host */
		free(sc->chost);
		if ((sc->chost = malloc(strlen(s) + 1)) == NULL) {
			seterr(sc, "%s", strerror(errno));
			return (-1);
		}
		strcpy(sc->chost, s);
	}
	return (0);
}
