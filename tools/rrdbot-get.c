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


#define RESEND_TIMEOUT      200         /* Time between SNMP resends */
#define DEFAULT_TIMEOUT     5000        /* Default timeout for SNMP response */
#define MAX_RETRIES         3           /* Number of SNMP packets we retry */

struct context
{
    int socket;                         /* The socket to use */
    unsigned char packet[0x1000];       /* The raw packet data to send */
    struct snmp_pdu pdu;                /* The actual request data */
    struct asn_oid oid_first;           /* The first OID we've done */

    struct sockaddr_any hostaddr;       /* The remote host */
    char* hostname;                     /* The remote host */

    uint64_t lastsend;                  /* Time of last send */
    int retries;                        /* Number of retries */
    uint64_t timeout;                   /* Receive timeout */

    int recursive;                      /* Whether we're going recursive or not */
    int numeric;                        /* Print raw data */
};

static struct context ctx;

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

    b.asn_ptr = ctx.packet;
    b.asn_len = sizeof(ctx.packet);

    if(snmp_pdu_encode(&ctx.pdu, &b))
        errx(1, "couldn't encode snmp buffer");

    ret = sendto(ctx.socket, ctx.packet, b.asn_ptr - ctx.packet, 0,
                 &SANY_ADDR(ctx.hostaddr), SANY_LEN(ctx.hostaddr));
    if(ret == -1)
        err(1, "couldn't send snmp packet to: %s", ctx.hostname);

    /* Some bookkeeping */
    ctx.retries++;
    ctx.lastsend = server_get_time();
}

static void
setup_req(char* uri)
{
    enum snmp_version version;
    const char* msg;
    char* scheme;
    char* copy;
    char* user;
    char* path;

    /* Parse the SNMP URI */
    copy = strdup(uri);
    msg = cfg_parse_uri(uri, &scheme, &ctx.hostname, &user, &path);
    if(msg)
        errx(2, "%s: %s", msg, copy);
    free(copy);

    ASSERT(ctx.hostname && path);

    /* Currently we only support SNMP pollers */
    msg = cfg_parse_scheme(scheme, &version);
    if(msg)
        errx(2, "%s: %s", msg, scheme);

    if(sock_any_pton(ctx.hostname, &ctx.hostaddr,
                     SANY_OPT_DEFPORT(161) | SANY_OPT_DEFLOCAL) == -1)
        err(1, "couldn't resolve host address (ignoring): %s", ctx.hostname);

    memset(&ctx.pdu, 0, sizeof(ctx.pdu));
    ctx.pdu.version = version;
    ctx.pdu.request_id = 0;
    ctx.pdu.type = ctx.recursive ? SNMP_PDU_GETNEXT : SNMP_PDU_GET;
    ctx.pdu.error_status = 0;
    ctx.pdu.error_index = 0;
    strlcpy(ctx.pdu.community, user ? user : "public",
            sizeof(ctx.pdu.community));


    /* And parse the OID */
    ctx.pdu.bindings[0].syntax = 0;
    memset(&(ctx.pdu.bindings[0].v), 0, sizeof(ctx.pdu.bindings[0].v));
    if(mib_parse(path, &(ctx.pdu.bindings[0].var)) == -1)
        errx(2, "invalid MIB: %s", path);

    /* Add an item to this request */
    ctx.pdu.nbindings = 1;

    /* Keep track of top for recursiveness */
    memcpy(&ctx.oid_first, &(ctx.pdu.bindings[0].var), sizeof(ctx.oid_first));

    /* Reset bookkeeping */
    ctx.retries = 0;
    ctx.lastsend = 0;
}

static void
setup_next(struct snmp_value* value)
{
    ctx.pdu.request_id++;
    ctx.pdu.type = SNMP_PDU_GETNEXT;

    /* And parse the OID */
    memcpy(&(ctx.pdu.bindings[0]), value, sizeof(struct snmp_value));
    ctx.pdu.bindings[0].syntax = 0;
    ctx.pdu.nbindings = 1;

    /* Reset bookkeeping */
    ctx.retries = 0;
    ctx.lastsend = 0;
}

static int
print_resp(struct snmp_pdu* pdu, uint64_t when)
{
    struct snmp_value* value;
    char *t;
    int i;

    ASSERT(ctx.pdu.request_id == pdu->request_id);

    for(i = 0; i < pdu->nbindings; i++)
    {
        value = &(pdu->bindings[i]);

        if(ctx.numeric)
            printf("%s", asn_oid2str(&(value->var)));
        else
            mib_format(&(value->var), stdout);

        printf(": ");

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

    ASSERT(ctx.socket == fd);

    /* Read in the packet */

    SANY_LEN(from) = sizeof(from);
    len = recvfrom(ctx.socket, ctx.packet, sizeof(ctx.packet), 0,
                   &SANY_ADDR(from), &SANY_LEN(from));
    if(len < 0)
    {
        if(errno != EAGAIN && errno != EWOULDBLOCK)
            err(1, "error receiving snmp packet from network");
    }

    if(sock_any_ntop(&from, hostname, MAXPATHLEN, 0) == -1)
        strcpy(hostname, "[UNKNOWN]");

    /* Now parse the packet */

    b.asn_ptr = ctx.packet;
    b.asn_len = len;

    ret = snmp_pdu_decode(&b, &pdu, &ip);
    if(ret != SNMP_CODE_OK)
        errx(1, "invalid snmp packet received from: %s", hostname);

    /* It needs to match something we're waiting for */
    if(pdu.request_id != ctx.pdu.request_id)
        return;

    /* Check for errors */
    if(pdu.error_status != SNMP_ERR_NOERROR)
    {
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
        subid = asn_compare_oid(&ctx.oid_first, &(val->var)) == 0 ||
                asn_is_suboid(&ctx.oid_first, &(val->var));
    }

    /* Print the packet values */
    if(!ctx.recursive || subid)
        ret = print_resp(&pdu, server_get_time());

    if(ret && ctx.recursive && subid)
    {
        /* If recursive, move onto next one */
        setup_next(&(pdu.bindings[pdu.nbindings - 1]));
        send_req();
        return;
    }

    server_stop ();
}

static int
send_timer(uint64_t when, void* arg)
{
    if(ctx.lastsend == 0)
        return 1;

    /* Check for timeouts */
    if(ctx.lastsend + ctx.timeout < when)
        errx(1, "timed out waiting for response from server");

    /* Resend packets when no response */
    if(ctx.retries < MAX_RETRIES && ctx.lastsend + RESEND_TIMEOUT < when)
        send_req();

    return 1;
}

/* -----------------------------------------------------------------------------
 * STARTUP
 */

static void
usage()
{
    fprintf(stderr, "usage: rrdbot-get [-Mnr] [-t timeout] [-m mibdir] snmp://community@host/oid\n");
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
    char* t;

    /* Defaults */
    memset(&ctx, 0, sizeof(ctx));
    ctx.socket = -1;
    ctx.timeout = DEFAULT_TIMEOUT;

    /* Parse the arguments nicely */
    while((ch = getopt(argc, argv, "m:Mnrt:V")) != -1)
    {
        switch(ch)
        {

        /* mib directory */
        case 'm':
            mib_directory = optarg;
            break;

        /* MIB load warnings */
        case 'M':
            mib_warnings = 1;
            break;

        /* Numeric output */
        case 'n':
            ctx.numeric = 1;
            break;

        /* SNMP walk (recursive)*/
        case 'r':
            ctx.recursive = 1;
            break;

        /* The timeout */
        case 't':
            ctx.timeout = strtoul(optarg, &t, 10);
            if(*t)
                errx(2, "invalid timeout: %s", optarg);
            ctx.timeout *= 1000;
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

    server_init();

    setup_req(argv[0]);

    /* Setup the SNMP socket */
    ctx.socket = socket(PF_INET, SOCK_DGRAM, 0);
    if(ctx.socket < 0)
        err(1, "couldn't open snmp socket");
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if(bind(ctx.socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        err(1, "couldn't listen on port");
    if(server_watch(ctx.socket, SERVER_READ, receive_resp, NULL) == -1)
        err(1, "couldn't listen on socket");

    /* Send off first request */
    send_req();

    /* We fire off the resend timer every 1/5 second */
    if(server_timer(RESEND_TIMEOUT, send_timer, NULL) == -1)
        err(1, "couldn't setup timer");

    /* Wait for responses */
    server_run();

    /* Done */
    server_unwatch(ctx.socket);
    close(ctx.socket);

    server_uninit();

    return 0;
}
