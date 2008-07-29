#ifndef SNMPENGINE_H_
#define SNMPENGINE_H_

#include <bsnmp/asn1.h>
#include <bsnmp/snmp.h>

typedef void (*snmp_response) (int request, int code, struct snmp_value *value, void *data);

void snmp_engine_init (const char *bind_address, int retries);

int  snmp_engine_request (const char* host, const char* community, int version,
                          uint64_t interval, uint64_t timeout, int reqtype,
                          struct asn_oid *oid, snmp_response func, void *data);

void snmp_engine_cancel (int reqid);

void snmp_engine_flush (void);

int  snmp_engine_sync (const char* host, const char* community, int version,
                       uint64_t interval, uint64_t timeout, int reqtype,
                       struct snmp_value *value);

void snmp_engine_stop (void);

int  snmp_engine_match (const struct snmp_value *value, const char *text);

#endif /*SNMPENGINE_H_*/
