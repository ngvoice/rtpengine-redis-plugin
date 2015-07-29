#ifndef RE_REDIT_MOD_H 
#define RE_REDIT_MOD_H

#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>

#include "./rtpengine/daemon/call.h"
#include "./rtpengine/daemon/log.h"

#define plog(prio,fmt,args...)									\
	do {											\
		openlog("rtpengine-redis-plugin", LOG_PID | LOG_NDELAY, _log_facility);		\
		ilog(prio, "[%s] " fmt, __FUNCTION__, ##args);				\
		openlog("rtpengine", LOG_PID | LOG_NDELAY, _log_facility);			\
	} while (0)

//syslog(prio | _log_facility, "[%s] " fmt, __FUNCTION__, ##__VA_ARGS__);

struct redis {
	int db;
	u_int16_t port;
	struct in_addr ip;
	char str_ip[16];
	redisContext *ctxt;
	redisAsyncContext *async_ctxt;
	struct event_base *eb;
	GThread *eb_thread;
};

void mod_redis_update(struct call *c, struct redis *r);
void mod_redis_delete(struct call *c, struct redis *r);
void mod_redis_wipe(struct redis *r);
int mod_redis_restore(struct callmaster *m, struct redis *r);
struct redis *mod_redis_new(struct in_addr ip, u_int16_t port, int database);


//struct *redis redis_new_mod(u_uint32 ip, u_int16_t port, int database);
//struct *redis mod_redis_new(int ip, int port, int database);

#endif
