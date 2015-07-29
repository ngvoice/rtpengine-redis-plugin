/*
 * cnxcc_storage.c
 *
 *  Created on: Jun 23, 2014
 *      Author: carlos
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <openssl/err.h>

#include "redis_storage.h"

static void __async_cmd_cb(redisAsyncContext *ctxt, void *r, void *privdata);
static void __async_disconnect_cb(const redisAsyncContext *c, int status);
static void __async_connect_cb(const redisAsyncContext *c, int status);
static int __redis_select_db(redisContext *ctxt, int db);
static int __insert_value(struct redis *redis, const char* cmd, redisReply **rpl);
static struct redis *__redis_connect_sync(struct redis *r);
static struct redis *__redis_connect_async(struct redis *redis);
static int __redis_insert_int_value(struct redis *redis, str *callid, const char* key, int32_t value, int async);
static int __redis_insert_uint_value(struct redis *redis, str *callid, const char* key, uint32_t value, int async);
static int __redis_insert_bin_value(struct redis *redis, str *callid, const char* key, const void *value, size_t size, int async);
static int __redis_insert_str_value(struct redis *redis, str *callid, const char* key, str *value, int async);
//static void *__event_dispatcher(void *p);

#define GOTO_LABEL_IF_ERR(_rpl_, _lbl_) if (!(_rpl_) || (_rpl_)->type == REDIS_REPLY_ERROR) \
											goto _lbl_; else \
											freeReplyObject((_rpl_);


int redis_insert_str_value(struct redis *redis, str *callid, const char* key, str *value) {
	return __redis_insert_str_value(redis, callid, key, value, 0);
}

int redis_insert_str_value_async(struct redis *redis, str *callid, const char* key, str *value) {
	return __redis_insert_str_value(redis, callid, key, value, 1);
}

static int __redis_insert_str_value(struct redis *redis, str *callid, const char* key, str *value, int async) {
	redisReply *rpl = NULL;
	int ret = -1;
	char cmd_buffer[CMD_BUFFER_SIZE];

	if (value == NULL) {
		plog(LOG_ERROR, "str value is null\n");
		return -1;
	}

	if (value->len == 0) {
		plog(LOG_WARN, "[%s] value is empty\n", key);
		return 1;
	}


	snprintf(cmd_buffer, sizeof(cmd_buffer), "HSET mp:%.*s %s %.*s", callid->len, callid->s, key, value->len, value->s);

	if (async)
		return redis_exec_async(redis, cmd_buffer) == REDIS_OK ? 1 : -1;

	ret = __insert_value(redis, cmd_buffer, &rpl);
	if (ret > 0)
		freeReplyObject(rpl);

	return ret;
}

int redis_insert_bin_value(struct redis *redis, str *callid, const char* key, const void *value, size_t size) {
	return __redis_insert_bin_value(redis, callid, key, value, size, 0);
}

int redis_insert_bin_value_async(struct redis *redis, str *callid, const char* key, const void *value, size_t size) {
	return __redis_insert_bin_value(redis, callid, key, value, size, 1);
}

static int __redis_insert_bin_value(struct redis *redis, str *callid, const char* key, const void *value, size_t size, int async) {
	redisReply *rpl = NULL;
	char str_call_id[512];

	if (value == NULL || size == 0) {
		plog(LOG_WARN, "[mp:%.*s %s] empty binary value\n", callid->len, callid->s, key);
		return 1;
	}

	memset(str_call_id, 0, sizeof(str_call_id));
	snprintf(str_call_id, sizeof(str_call_id), "%.*s", callid->len, callid->s);

	if (async)
		return redisAsyncCommand(redis->async_ctxt, __async_cmd_cb, NULL,
				"HSET mp:%s %s %b", str_call_id, key, value, size) == REDIS_OK ? 1 : -1;

	rpl = redisCommand(redis->ctxt, "HSET mp:%s %s %b", str_call_id, key, value, size);

	if (!rpl || rpl->type == REDIS_REPLY_ERROR) {
		if (!rpl)
			plog(LOG_ERR, "%s", redis->ctxt->errstr);
		else {
			plog(LOG_ERR, "%.*s", rpl->len, rpl->str);
			freeReplyObject(rpl);
		}

		// reconnect on error
		__redis_connect_sync(redis);
		return -1;
	}

	freeReplyObject(rpl);
	return 1;
}

int redis_insert_int_value(struct redis *redis, str *callid, const char* key, int32_t value) {
	return __redis_insert_int_value(redis, callid, key, value, 0);
}

int redis_insert_int_value_async(struct redis *redis, str *callid, const char* key, int32_t value) {
	return __redis_insert_int_value(redis, callid, key, value, 1);
}

static int __redis_insert_int_value(struct redis *redis, str *callid, const char* key, int32_t value, int async) {
	redisReply *rpl = NULL;
	int ret = -1;
	char cmd_buffer[1024];

	snprintf(cmd_buffer, sizeof(cmd_buffer), "HSET mp:%.*s %s %d", callid->len, callid->s, key, value);

	if (async)
		return redis_exec_async(redis, cmd_buffer) == REDIS_OK ? 1 : -1;

	ret = __insert_value(redis, cmd_buffer, &rpl);
	if (ret > 0)
		freeReplyObject(rpl);

	return ret;
}

int redis_insert_uint_value(struct redis *redis, str *callid, const char* key, uint32_t value) {
	return __redis_insert_uint_value(redis, callid, key, value, 0);
}

int redis_insert_uint_value_async(struct redis *redis, str *callid, const char* key, uint32_t value) {
	return __redis_insert_uint_value(redis, callid, key, value, 1);
}

static int __redis_insert_uint_value(struct redis *redis, str *callid, const char* key, uint32_t value, int async) {
	redisReply *rpl = NULL;
	int ret = -1;
	char cmd_buffer[1024];

	snprintf(cmd_buffer, sizeof(cmd_buffer), "HSET mp:%.*s %s %u", callid->len, callid->s, key, value);

	if (async)
		return redis_exec_async(redis, cmd_buffer) == REDIS_OK ? 1 : -1;

	ret = __insert_value(redis, cmd_buffer, &rpl);
	if (ret > 0)
		freeReplyObject(rpl);

	return ret;
}

static int __insert_value(struct redis *redis, const char* cmd, redisReply **rpl) {
	*rpl = redisCommand(redis->ctxt, cmd);

//	plog(LOG_INFO, "cmd: [%s]\n", cmd);

	if (!(*rpl) || (*rpl)->type == REDIS_REPLY_ERROR) {
		if (!*rpl)
			plog(LOG_ERR, "[%s]: %s", cmd, redis->ctxt->errstr);
		else {
			plog(LOG_ERR, "[%s]: %.*s", cmd, (*rpl)->len, (*rpl)->str);
			freeReplyObject(*rpl);
		}

		// reconnect on error
		__redis_connect_sync(redis);
		return -1;
	}

	return 1;
}

static struct redis *__alloc_redis(struct in_addr ip, uint16_t port, int db) {
	struct redis *redis = g_malloc0(sizeof(struct redis));
	char *str_ip = inet_ntoa(ip);

	redis->ip = ip;
	redis->port = port;
	redis->db = db;
	redis->ctxt = NULL;
	redis->async_ctxt = NULL;

	strcpy(redis->str_ip, str_ip);

	return redis;
}

static struct redis *__redis_connect_async(struct redis *redis) {
	redis->eb = event_base_new();

	plog(LOG_INFO, "Connecting (ASYNC) to Redis at %s:%d", redis->str_ip, redis->port);

	redis->async_ctxt = redisAsyncConnect(redis->str_ip, redis->port);

	if (redis->async_ctxt->err) {
		plog(LOG_ERR, "%s\n", redis->async_ctxt->errstr);
		return NULL;
	}

	redisLibeventAttach(redis->async_ctxt, redis->eb);

	redisAsyncSetConnectCallback(redis->async_ctxt, __async_connect_cb);
	redisAsyncSetDisconnectCallback(redis->async_ctxt, __async_disconnect_cb);
	redisAsyncCommand(redis->async_ctxt, NULL, NULL, "SELECT %d", redis->db);

//	redis->eb_thread =  g_thread_new("event dispatcher", __event_dispatcher, redis);

	return redis;
}

/*
static void *__event_dispatcher(void *p) {
	struct redis *redis = p;
	plog(LOG_ERR, "THREAD STARTED: %s\n", redis->str_ip);
	event_base_dispatch(redis->eb);
	return NULL;
}
*/

struct redis *redis_connect_all(struct redis *redis) {
	//return __redis_connect_sync(__redis_connect_async(redis));
	return __redis_connect_async(__redis_connect_sync(redis));
}

struct redis *redis_connect(struct in_addr ip, uint16_t port, int db) {
	return redis_connect_all(__alloc_redis(ip, port, db));
}

static struct redis *__redis_connect_sync(struct redis *r) {
	struct timeval timeout = { 1, 500000 }; // 1.5 seconds

	plog(LOG_INFO, "Connecting to Redis at %s:%d", r->str_ip, r->port);

	if (r->ctxt)
		redisFree(r->ctxt);

	r->ctxt = redisConnectWithTimeout(r->str_ip, r->port, timeout);

	if (r->ctxt == NULL || r->ctxt->err) {
		if (!r->ctxt)
			plog(LOG_ERR, "Connection error: can't allocate Redis context");
		else {
			plog(LOG_ERR, "Connection error: %s", r->ctxt->errstr);
			redisFree(r->ctxt);
		}

		return NULL;
	}

	if (!__redis_select_db(r->ctxt, r->db))
		return NULL;

	return r;
}

static int __redis_select_db(redisContext *ctxt, int db) {
	redisReply *rpl;
	rpl = redisCommand(ctxt, "SELECT %d", db);

	if (!rpl || rpl->type == REDIS_REPLY_ERROR) {
		if (!rpl)
			plog(LOG_ERR, "%s", ctxt->errstr);
		else {
			plog(LOG_ERR, "%.*s", rpl->len, rpl->str);
			freeReplyObject(rpl);
		}
		return -1;
	}

	return 1;
}

int redis_exec_async(struct redis *redis, const char *cmd) {
	return redisAsyncCommand(redis->async_ctxt, NULL, NULL, cmd);
}

int redis_exec(struct redis *redis, const char *cmd, redisReply **rpl) {
	*rpl = redisCommand(redis->ctxt, cmd);

	if (!(*rpl) || (*rpl)->type == REDIS_REPLY_ERROR) {
		if (!*rpl)
			plog(LOG_ERR, "%s", redis->ctxt->errstr);
		else {
			plog(LOG_ERR, "%.*s", (*rpl)->len, (*rpl)->str);
			freeReplyObject(*rpl);
		}

		// reconnect on error
		redis_connect_all(redis);
		return -1;
	}

	return 1;
}

int redis_remove_member(struct redis *redis, str *callid) {
	redisReply *rpl = NULL;
	char cmd_buffer[1024];
	int ret;

	snprintf(cmd_buffer, sizeof(cmd_buffer), "SREM mp:calls %.*s",callid->len, callid->s);

	ret = redis_exec(redis, cmd_buffer, &rpl);

	if (ret > 0)
		freeReplyObject(rpl);

	return ret;
}

int redis_get_str(struct redis *redis, const char *instruction, str *identifier, const char *key, str *value) {
	redisReply *rpl = NULL;
	char cmd_buffer[1024];

	snprintf(cmd_buffer, sizeof(cmd_buffer), "%s mp:%.*s %s", instruction, identifier->len, identifier->s, key);

	value->s = NULL;
	value->len = 0;

	if (redis_exec(redis, cmd_buffer , &rpl) < 0)
		return -1;

	if (rpl->type != REDIS_REPLY_STRING && rpl->type != REDIS_REPLY_NIL) {
		plog(LOG_ERR,"Redis reply to [%s] is not a string/nil: type[%d]", cmd_buffer, rpl->type);
		freeReplyObject(rpl);
		return -1;
	}

	if (rpl->type == REDIS_REPLY_NIL) {
		plog(LOG_INFO,"Value of %s is (nil)", key);
		goto done;
	}

	if (rpl->len <= 0) {
		plog(LOG_ERR, "RPL len is equal to %d\n", rpl->len);
		goto done;
	}

	value->s = g_malloc0(rpl->len);
	value->len = rpl->len;
	memcpy(value->s, rpl->str, rpl->len);

done:
	freeReplyObject(rpl);

	//plog(LOG_INFO, "Got STRING value: %s=[%.*s]", key, value->len, value->s);
	return 1;
}

/*int redis_get_ustr(struct redis *redis, const char *instruction, str *identifier, const char *key, ustr *value) {
	redisReply *rpl = NULL;
	char cmd_buffer[1024];

	snprintf(cmd_buffer, sizeof(cmd_buffer), "%s mp:%.*s %s", instruction, identifier->len, identifier->s, key);

	value->s = NULL;
	value->len = 0;

	if (redis_exec(redis, cmd_buffer , &rpl) < 0)
		return -1;

	if (rpl->type != REDIS_REPLY_STRING && rpl->type != REDIS_REPLY_NIL) {
		plog(LOG_ERR,"Redis reply to [%s] is not a string/nil: type[%d]", cmd_buffer, rpl->type);
		freeReplyObject(rpl);
		return -1;
	}

	if (rpl->type == REDIS_REPLY_NIL) {
		plog(LOG_INFO,"Value of %s is (nil)", key);
		goto done;
	}

	if (rpl->len <= 0) {
		plog(LOG_ERR, "RPL len is equal to %d\n", rpl->len);
		goto done;
	}

	value->s = g_malloc0(rpl->len);
	value->len = rpl->len;
	memcpy(value->s, rpl->str, rpl->len);

done:
	freeReplyObject(rpl);

	//plog(LOG_INFO, "Got STRING value: %s=[%.*s]", key, value->len, value->s);
	return 1;
}
*/

int redis_get_int(struct redis *redis, const char *instruction, str *callid, const char *key, int *value) {
	redisReply *rpl = NULL;
	char cmd_buffer[1024];
	snprintf(cmd_buffer, sizeof(cmd_buffer), "%s mp:%.*s %s", instruction, callid->len, callid->s, key);

	if (redis_exec(redis, cmd_buffer, &rpl) < 0)
		return -1;

	if (rpl->type == REDIS_REPLY_INTEGER)
		*value = rpl->integer;
	else if (rpl->type == REDIS_REPLY_NIL)
		*value = 0;
	else {
		*value = atoi(rpl->str);
	}

	freeReplyObject(rpl);

	//plog(LOG_INFO, "Got INT value: %s=%d", key, *value);
	return 1;
}

int redis_get_uint(struct redis *redis, const char *instruction, str *callid, const char *key, unsigned int *value) {
	redisReply *rpl = NULL;
	char cmd_buffer[1024];
	snprintf(cmd_buffer, sizeof(cmd_buffer), "%s mp:%.*s %s", instruction, callid->len, callid->s, key);

	if (redis_exec(redis, cmd_buffer, &rpl) < 0)
		return -1;

	if (rpl->type == REDIS_REPLY_INTEGER)
		*value = rpl->integer;
	else if (rpl->type == REDIS_REPLY_NIL)
		*value = 0;
	else {
		*value = atoi(rpl->str);
	}

	freeReplyObject(rpl);

	//plog(LOG_INFO, "Got INT value: %s=%d", key, *value);
	return 1;
}

static void __async_connect_cb(const redisAsyncContext *c, int status) {
	if (status != REDIS_OK) {
		plog(LOG_ERR, "error connecting to Redis db in async mode\n");
		return;
	}

	plog(LOG_INFO, "connected to Redis in async mode\n");
}

static void __async_disconnect_cb(const redisAsyncContext *c, int status) {
	plog(LOG_ERR, "async DB connection was lost\n");
}

static void __async_cmd_cb(redisAsyncContext *ctxt, void *r, void *privdata) {
	redisReply *rpl = r;

	if (!rpl)
		plog(LOG_ERR, "async command error: %s", ctxt->errstr);
	else if (rpl->type == REDIS_REPLY_ERROR)
		plog(LOG_ERR, "async command error: %.*s", rpl->len, rpl->str);

}

int redis_restore_fingerprint(struct redis *redis, str *fingerprint) {
	str identifier = { "dtls-fingerprint", sizeof("dtls-fingerprint") - 1 };

	if (redis_get_str(redis, "HGET", &identifier, "value", fingerprint) < 0)
		return -1;

	if (!fingerprint->s) {
		plog(LOG_INFO, "dtls-fingerprint is empty");
		return 0;
	}

	return 1;
}

int redis_insert_fingerprint(struct redis *redis, unsigned char *fingerprint, size_t length) {
	str identifier = { "dtls-fingerprint", sizeof("dtls-fingerprint") - 1 };

	if (redis_insert_bin_value(redis, &identifier, "value", fingerprint, length) < 0)
		return -1;

	return 1;
}

int redis_restore_expires(struct redis *redis, time_t *value) {
	str identifier = { "cert-expires", sizeof("cert-expires") - 1 };
	str aux;

	if (redis_get_str(redis, "HGET", &identifier, "value", &aux) < 0)
		return -1;

	if (!aux.s) {
		plog(LOG_INFO, "expires is empty");
		return 0;
	}

	COPY_AND_FREE(value, aux);

	return 1;
}

int redis_insert_expires(struct redis *redis, time_t *value) {
	str identifier = { "cert-expires", sizeof("cert-expires") - 1 };

	if (redis_insert_bin_value(redis, &identifier, "value", value, sizeof(*value)) < 0)
		return -1;

	return 1;
}

int redis_restore_cert(struct redis *redis, X509 **x509) {
	str identifier = { "cert", 4 };
	str value;
	BIO *bio;

	if (redis_get_str(redis, "HGET", &identifier, "pem", &value) < 0)
		return -1;

	if (!value.s) {
		plog(LOG_INFO, "cert is empty");
		return 0;
	}

	// Create a read-only BIO backed by the supplied memory buffer
	bio = BIO_new_mem_buf((void*) value.s, value.len);

	PEM_read_bio_X509(bio, x509, NULL, NULL);

	// Cleanup
	BIO_free(bio);

	g_free(value.s);
	return 1;
}

int redis_insert_cert(struct redis *redis, X509 *x509) {
	redisReply *rpl;
	unsigned char certificate[2048];
	BIO *b64;
	int res;

	b64 = BIO_new (BIO_s_mem());
	PEM_write_bio_X509(b64, x509);
	res = BIO_read(b64, certificate, sizeof(certificate));
	rpl = redisCommand(redis->ctxt, "HSET mp:cert pem %b", certificate, res);
	BIO_free(b64);

	if (!rpl || rpl->type == REDIS_REPLY_ERROR) {
		if (!rpl)
			plog(LOG_ERR, "%s", redis->ctxt->errstr);
		else {
			plog(LOG_ERR, "%.*s", rpl->len, rpl->str);
			freeReplyObject(rpl);
		}

		// reconnect on error
		redis_connect_all(redis);
		return -1;
	}

	if (rpl)
		freeReplyObject(rpl);

	return 1;
}

int redis_restore_pkey(struct redis *redis, EVP_PKEY **pkey) {
	str identifier = { "pkey", 4 };
	str value;
	BIO *bio;

	if (redis_get_str(redis, "HGET", &identifier, "der", &value) < 0)
		return -1;

	if (!value.s || value.len == 0) {
		plog(LOG_INFO, "pkey is empty");
		return 0;
	}

	// Create a read-only BIO backed by the supplied memory buffer
	bio = BIO_new_mem_buf((void*) value.s, value.len);
	PEM_read_bio_PrivateKey(bio, pkey, NULL, NULL);
	//PEM_read_bio_PUBKEY(bio, pkey, NULL, NULL);

	if (!pkey) {
		char buffer[512];
		ERR_error_string(ERR_get_error(), buffer);
		plog(LOG_ERR, "pkey pointer is NULL: %s", buffer);
		return -1;
	}

	// Cleanup
	BIO_free(bio);

	g_free(value.s);
	return 1;
}

int redis_insert_pkey(struct redis *redis, EVP_PKEY *pkey) {
	redisReply *rpl;
	unsigned char pem_key[2048];
	BIO *b64;
	int res;

/*
	pkeyLen = i2d_PublicKey(pkey, NULL);
	buffer = (unsigned char *) g_malloc0(pkeyLen + 1);
	tempBuf = buffer;
	i2d_PublicKey(pkey, &tempBuf);
*/
	b64 = BIO_new (BIO_s_mem());
	PEM_write_bio_PrivateKey(b64, pkey, 0, 0, 0, 0, 0);

	//PEM_write_bio_PUBKEY(b64, pkey);

	res = BIO_read(b64, pem_key, sizeof(pem_key));

	rpl = redisCommand(redis->ctxt, "HSET mp:pkey der %b", b64, res);

	BIO_free(b64);

	if (!rpl || rpl->type == REDIS_REPLY_ERROR) {
		if (!rpl)
			plog(LOG_ERR, "%s", redis->ctxt->errstr);
		else {
			plog(LOG_ERR, "%.*s", rpl->len, rpl->str);
			freeReplyObject(rpl);
		}

		// reconnect on error
		redis_connect_all(redis);
		return -1;
	}

	if (rpl)
		freeReplyObject(rpl);

	return 1;
}

