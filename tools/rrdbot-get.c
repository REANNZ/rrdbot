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
 *
 */

#include "usuals.h"
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <err.h>

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>
#include <mib/mib-parser.h>

#include "sock-any.h"
#include "server-mainloop.h"
#include "config-parser.h"

/* The socket to use */
static int snmp_socket = -1;

/* Since we only deal with one packet at a time, global buffer */
static unsigned char snmp_buffer[0x1000];

/* The actual request data */
static struct snmp_pdu snmp_data;

/* The first OID we've done */
static struct asn_oid oid_first;

/* The remote host */
static struct sockaddr_any snmp_hostaddr;
static char* snmp_hostname = NULL;

static int retries = 0;

static int recursive = 0;   /* Whether we're going recursive or not */
static int numeric = 0;     /* Print raw data */

/* -----------------------------------------------------------------------------
 * DUMMY CONFIG FUNCTIONS
 */

int
cfg_value(const char* filename, const char* header, const char* name,
          char* value, void* data)
{
    return 0;
}

int
cfg_error(const char* filename, const char* errmsg, void* data)
{
    return 0;
}

/* -----------------------------------------------------------------------------
 * SNMP ENGINE
 */

static void
send_req()
{
    struct asn_buf b;
    ssize_t ret;

    b.asn_ptr = snmp_buffer;
    b.asn_len = sizeof(snmp_buffer);

    if(snmp_pdu_encode(&snmp_data, &b))
        errx(1, "couldn't encode snmp buffer");

    ret = sendto(snmp_socket, snmp_buffer, b.asn_ptr - snmp_buffer, 0,
                 &SANY_ADDR(snmp_hostaddr), SANY_LEN(snmp_hostaddr));
    if(ret == -1)
        err(1, "couldn't send snmp packet to: %s", snmp_hostname);

}

static void
setup_req(char* uri)
{
    const char* msg;
    char* scheme;
    char* copy;
    char* user;
    char* path;

    /* Parse the SNMP URI */
    copy = strdup(uri);
    msg = cfg_parse_uri(uri, &scheme, &snmp_hostname, &user, &path);
    if(msg)
        errx(2, "%s: %s", msg, copy);
    free(copy);

    ASSERT(host && path);

    /* Currently we only support SNMP pollers */
    if(strcmp(scheme, "snmp") != 0)
        errx(2, "invalid scheme: %s", scheme);

    if(sock_any_pton(snmp_hostname, &snmp_hostaddr,
                     SANY_OPT_DEFPORT(161) | SANY_OPT_DEFLOCAL) == -1)
        err(1, "couldn't resolve host address (ignoring): %s", snmp_hostname);

    memset(&snmp_data, 0, sizeof(snmp_data));
    snmp_data.version = 1;
    snmp_data.request_id = 0;
    snmp_data.type = recursive ? SNMP_PDU_GETNEXT : SNMP_PDU_GET;
    snmp_data.error_status = 0;
    snmp_data.error_index = 0;
    strlcpy(snmp_data.community, user ? user : "public",
            sizeof(snmp_data.community));


    /* And parse the OID */
    snmp_data.bindings[0].syntax = 0;
    memset(&(snmp_data.bindings[0].v), 0, sizeof(snmp_data.bindings[0].v));
    if(mib_parse(path, &(snmp_data.bindings[0].var)) == -1)
        errx(2, "invalid MIB: %s", path);

    /* Add an item to this request */
    snmp_data.nbindings = 1;

    /* Keep track of top for recursiveness */
    memcpy(&oid_first, &(snmp_data.bindings[0].var), sizeof(oid_first));

}

static void
setup_next(struct snmp_value* value)
{
    snmp_data.request_id++;
    snmp_data.type = SNMP_PDU_GETNEXT;

    /* And parse the OID */
    memcpy(&(snmp_data.bindings[0]), value, sizeof(struct snmp_value));
    snmp_data.bindings[0].syntax = 0;
    snmp_data.nbindings = 1;
}


static int
print_resp(struct snmp_pdu* pdu, uint64_t when)
{
    struct snmp_value* value;
    char *t;
    int i;

    ASSERT(req->id == pdu->request_id);

    for(i = 0; i < pdu->nbindings; i++)
    {
        value = &(pdu->bindings[i]);

        if(numeric)
            printf("%s: ", asn_oid2str(&(value->var)));
        else
            mib_format(&(value->var), stdout);

        switch(value->syntax)
        {
        case SNMP_SYNTAX_NULL:
            printf("[null]\n");
            break;
        case SNMP_SYNTAX_INTEGER:
            printf("%d\n", value->v.integer);
            break;
        case SNMP_SYNTAX_COUNTER:
        case SNMP_SYNTAX_GAUGE:
        case SNMP_SYNTAX_TIMETICKS:
            printf("%d\n", value->v.uint32);
            break;
        case SNMP_SYNTAX_COUNTER64:
            printf("%lld\n", value->v.counter64);
            break;
        case SNMP_SYNTAX_OCTETSTRING:
            t = xcalloc(value->v.octetstring.len + 1);
            memcpy(t, value->v.octetstring.octets, value->v.octetstring.len);
            printf("%s\n", t);
            free(t);
            break;
        case SNMP_SYNTAX_OID:
            printf("%s\n", asn_oid2str(&(value->v.oid)));
            break;
        case SNMP_SYNTAX_IPADDRESS:
            printf("%c.%c.%c.%c\n", value->v.ipaddress[0], value->v.ipaddress[1],
                   value->v.ipaddress[2], value->v.ipaddress[3]);
            break;
        case SNMP_SYNTAX_NOSUCHOBJECT:
            printf("[field not available on snmp server]\n");
            break;
        case SNMP_SYNTAX_NOSUCHINSTANCE:
            printf("[no such instance on snmp server]\n");
            break;
        case SNMP_SYNTAX_ENDOFMIBVIEW:
            return 0;
        default:
            printf("[unknown]\n");
            break;
        }
    }

    return 1;
}

static void
receive_resp(int fd, int type, void* arg)
{
    char hostname[MAXPATHLEN];
    struct sockaddr_any from;
    struct snmp_pdu pdu;
    struct snmp_value *val;
    struct asn_buf b;
    const char* msg;
    int len, ret, subid;
    int32_t ip;

    ASSERT(snmp_socket == fd);

    /* Read in the packet */

    SANY_LEN(from) = sizeof(from);
    len = recvfrom(snmp_socket, snmp_buffer, sizeof(snmp_buffer), 0,
                   &SANY_ADDR(from), &SANY_LEN(from));
    if(len < 0)
    {
        if(errno != EAGAIN && errno != EWOULDBLOCK)
            err(1, "error receiving snmp packet from network");
    }

    if(sock_any_ntop(&from, hostname, MAXPATHLEN, 0) == -1)
        strcpy(hostname, "[UNKNOWN]");

    /* Now parse the packet */

    b.asn_ptr = snmp_buffer;
    b.asn_len = len;

    ret = snmp_pdu_decode(&b, &pdu, &ip);
    if(ret != SNMP_CODE_OK)
        errx(1, "invalid snmp packet received from: %s", hostname);

    /* It needs to match something we're waiting for */
    if(pdu.request_id != snmp_data.request_id)
        return;

    /* Check for errors */
    if(pdu.error_status != SNMP_ERR_NOERROR)
    {
        snmp_pdu_dump (&pdu);
        msg = snmp_get_errmsg (pdu.error_status);
        if(msg)
            errx(1, "snmp error from host '%s': %s", hostname, msg);
        else
            errx(1, "unknown snmp error from host '%s': %d", hostname, pdu.error_status);
        return;
    }

    subid = ret = 1;

    if(pdu.nbindings > 0)
    {
        val = &(pdu.bindings[pdu.nbindings - 1]);
        subid = asn_compare_oid(&oid_first, &(val->var)) == 0 ||
                asn_is_suboid(&oid_first, &(val->var));
    }

    /* Print the packet values */
    if(!recursive || subid)
        ret = print_resp(&pdu, server_get_time());

    if(ret && recursive && subid)
    {
        /* If recursive, move onto next one */
        setup_next(&(pdu.bindings[pdu.nbindings - 1]));
        send_req();
        return;
    }

    server_stop ();
}

/* -----------------------------------------------------------------------------
 * STARTUP
 */

static void
usage()
{
    fprintf(stderr, "usage: rrdbot-get [-nr] snmp://community@host/oid\n");
    fprintf(stderr, "       rrdbot-get -V\n");
    exit(2);
}

static void
version()
{
    printf("rrdbot-get (version %s)\n", VERSION);
    exit(0);
}

int
main(int argc, char* argv[])
{
    struct sockaddr_in addr;
    char ch;

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "nrV")) != -1)
    {
        switch(ch)
        {

        /* Numeric output */
        case 'n':
            numeric = 1;
            break;

        /* SNMP walk (recursive)*/
        case 'r':
            recursive = 1;
            break;

        /* Print version number */
        case 'V':
            version();
            break;

        /* Usage information */
        case '?':
        default:
            usage();
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if(argc != 1)
        usage();

    setup_req (argv[0]);

    /* Setup the SNMP socket */
    snmp_socket = socket(PF_INET, SOCK_DGRAM, 0);
    if(snmp_socket < 0)
        err(1, "couldn't open snmp socket");
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if(bind(snmp_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        err(1, "couldn't listen on port");
    if(server_watch(snmp_socket, SERVER_READ, receive_resp, NULL) == -1)
        err(1, "couldn't listen on socket");

    send_req();

    server_run();

    return 0;
}
