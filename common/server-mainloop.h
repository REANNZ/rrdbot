
#ifndef __SERVER_MAINLOOP_H__
#define __SERVER_MAINLOOP_H__

#include <stdint.h>

/* TODO: Prefix functions with svr */

#define SERVER_READ       0x01
#define SERVER_WRITE      0x02

typedef void (*server_socket_callback)(int fd, int type, void* arg);
typedef int (*server_timer_callback)(uint64_t when, void* arg);

void    server_init();
void    server_uninit();
int     server_run();
void    server_stop();
int     server_stopped();
int     server_watch(int fd, int type, server_socket_callback callback, void* arg);
void    server_unwatch(int fd);
int     server_timer(int length, server_timer_callback callback, void* arg);
int     server_oneshot(int length, server_timer_callback callback, void* arg);
uint64_t server_get_time();

#endif /* __SERVER_MAINLOOP_H__ */
