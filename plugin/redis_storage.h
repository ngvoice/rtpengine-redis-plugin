/*
 * cnxcc_storage.h
 *
 *  Created on: Jun 23, 2014
 *      Author: carlos
 */

#ifndef REDIS_STORAGE_H_
#define REDIS_STORAGE_H_

#include <sys/types.h>
#include <hiredis/hiredis.h>
#include <arpa/inet.h>

#include "re_redis_mod.h"
#include "../rtpengine/daemon/str.h"

#define CMD_BUFFER_SIZE 2048
#define COPY_AND_FREE(_to_, _from_) if (_from_.s) { memcpy(_to_, _from_.s, _from_.len); g_free(_from_.s); }

struct _ustr {
	unsigned char *s;
	int len;
};

typedef struct _ustr ustr;

// connection functions
struct redis *redis_connect(struct in_addr ip, uint16_t port, int db);
struct redis *redis_connect_all(struct redis *redis);

// set functions
//int redis_insert_int_value(struct redis *redis, str *callid, const char* key, int value);
int redis_insert_int_value(struct redis *redis, str *callid, const char* key, int32_t value);
int redis_insert_int_value_async(struct redis *redis, str *callid, const char* key, int32_t value);

int redis_insert_uint_value(struct redis *redis, str *callid, const char* key, uint32_t value);
int redis_insert_uint_value_async(struct redis *redis, str *callid, const char* key, uint32_t value);

int redis_insert_str_value(struct redis *redis, str *callid, const char* key, str *value);
int redis_insert_str_value_async(struct redis *redis, str *callid, const char* key, str *value);

int redis_insert_bin_value(struct redis *redis, str *callid, const char* key, const void *value, size_t size);
int redis_insert_bin_value_async(struct redis *redis, str *callid, const char* key, const void *value, size_t size);

// get functions
int redis_exec(struct redis *redis, const char *cmd, redisReply **rpl);
int redis_exec_async(struct redis *redis, const char *cmd);
int redis_get_int(struct redis *redis, const char *instruction, str *callid, const char *key, int *value);
int redis_get_uint(struct redis *redis, const char *instruction, str *callid, const char *key, unsigned int *value);
int redis_get_str(struct redis *redis, const char *instruction, str *callid, const char *key, str *value);
//
int redis_remove_mp_entry(struct redis *redis, str *callid);
int redis_remove_member(struct redis *redis, str *callid);

int redis_insert_cert(struct redis *redis, X509 *x509);
int redis_restore_cert(struct redis *redis, X509 **x509);

int redis_insert_pkey(struct redis *redis, EVP_PKEY *pkey);
int redis_restore_pkey(struct redis *redis, EVP_PKEY **pkey);

int redis_insert_expires(struct redis *redis, time_t *value);
int redis_restore_expires(struct redis *redis, time_t *value);

int redis_insert_fingerprint(struct redis *redis, unsigned char *fingerprint, size_t length);
int redis_restore_fingerprint(struct redis *redis, str *fingerprint);

#endif /* REDIS_STORAGE_H_ */
