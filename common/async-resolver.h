
#ifndef __ASYNC_RESOLVER_H__
#define __ASYNC_RESOLVER_H__

#include <netdb.h>

typedef void (*async_resolve_callback)(int ecode, struct addrinfo* ai, void* arg);

int  async_resolver_init();
void async_resolver_uninit();

void async_resolver_queue(const char* hostname, const char* servname,
                          async_resolve_callback cb, void* arg);


#endif /* __ASYNC_RESOLVER_H__ */
