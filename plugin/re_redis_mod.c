#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>

#include "../rtpengine/daemon/sdp.h"
#include "../rtpengine/daemon/call.h"
#include "re_redis_mod.h"
#include "redis_storage.h"

char *__module_version = "redis/8";

#define DECL_STRUCT_SIZE(_s_) unsigned long __size_struct_ ## _s_ = sizeof(struct _s_);

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)
#define MEMBER_OFFSET(type, member) &(((type *)0)->member)

#define DECL_MEMBER_OFFSET(_s_, _m_) unsigned long __offset_struct_ ## _s_ ## _ ## _m_ =  (unsigned long) MEMBER_OFFSET(struct _s_, _m_);
#define DECL_MEMBER_SIZE(_s_, _m_) unsigned long __size_struct_ ## _s_ ## _ ## _m_ = MEMBER_SIZE(struct _s_, _m_);
#define DECL_MEMBER_OFFSET_SIZE(_s_, _m_) DECL_MEMBER_OFFSET(_s_, _m_) \
                                          DECL_MEMBER_SIZE(_s_, _m_)

DECL_STRUCT_SIZE(call);
DECL_STRUCT_SIZE(packet_stream);
DECL_STRUCT_SIZE(call_media);
DECL_STRUCT_SIZE(call_monologue);
DECL_STRUCT_SIZE(crypto_suite);
DECL_STRUCT_SIZE(crypto_context);

DECL_MEMBER_OFFSET_SIZE(call, callmaster);
DECL_MEMBER_OFFSET_SIZE(call, master_lock);
DECL_MEMBER_OFFSET_SIZE(call, monologues);
DECL_MEMBER_OFFSET_SIZE(call, tags);
DECL_MEMBER_OFFSET_SIZE(call, streams);
DECL_MEMBER_OFFSET_SIZE(call, stream_fds);
DECL_MEMBER_OFFSET_SIZE(call, dtls_cert);
DECL_MEMBER_OFFSET_SIZE(call, callid);
DECL_MEMBER_OFFSET_SIZE(call, last_signal);

DECL_MEMBER_OFFSET_SIZE(packet_stream, media);
DECL_MEMBER_OFFSET_SIZE(packet_stream, call);
DECL_MEMBER_OFFSET_SIZE(packet_stream, rtcp_sibling);
DECL_MEMBER_OFFSET_SIZE(packet_stream, handler);
DECL_MEMBER_OFFSET_SIZE(packet_stream, crypto);
DECL_MEMBER_OFFSET_SIZE(packet_stream, dtls_cert);
DECL_MEMBER_OFFSET_SIZE(packet_stream, ps_flags);

DECL_MEMBER_OFFSET_SIZE(call_media, monologue);
DECL_MEMBER_OFFSET_SIZE(call_media, call);
DECL_MEMBER_OFFSET_SIZE(call_media, protocol);
DECL_MEMBER_OFFSET_SIZE(call_media, fingerprint);
DECL_MEMBER_OFFSET_SIZE(call_media, streams);
DECL_MEMBER_OFFSET_SIZE(call_media, media_flags);

DECL_MEMBER_OFFSET_SIZE(call_monologue, call);
DECL_MEMBER_OFFSET_SIZE(call_monologue, tag);
DECL_MEMBER_OFFSET_SIZE(call_monologue, created);
DECL_MEMBER_OFFSET_SIZE(call_monologue, other_tags);
DECL_MEMBER_OFFSET_SIZE(call_monologue, active_dialogue);
DECL_MEMBER_OFFSET_SIZE(call_monologue, medias);

DECL_MEMBER_OFFSET_SIZE(stream_fd, fd);
DECL_MEMBER_OFFSET_SIZE(stream_fd, call);
DECL_MEMBER_OFFSET_SIZE(stream_fd, stream);
DECL_MEMBER_OFFSET_SIZE(stream_fd, dtls);

extern const struct transport_protocol transport_protocols[];
extern const struct crypto_suite crypto_suites[];
extern const int num_crypto_suites;

static void __print_flags(const char *title, struct stream_params *sp);

static int __insert_stream_params(struct redis *redis, str* callid, int stream_id, struct stream_params *sp, uint16_t bridge_port);
static int __retrieve_stream_params(struct redis *redis, str* callid, int stream_id, struct stream_params *sp, uint16_t *bridge_port);
static void __streams_free(GQueue *q);
static int __register_callid(struct redis *redis, str* callid);
static int __retrieve_call_list(struct redis *redis, struct callmaster *cm, str **list, int *length);
static const char *__crypto_find_name(const struct crypto_suite *ptr);
static int __process_call(str *callid, struct callmaster *cm, struct stream_params *sp, str *ft, str *tt, struct sdp_ng_flags *flags, enum call_opmode op_mode);
static void __fill_flag(struct sdp_ng_flags *flags, struct stream_params *sp);

void mod_redis_update(struct call *call, struct redis *redis) {
	struct packet_stream *ps;
	struct call_media *m;
	GSList *monologue_iter;
	GList *ml_media_iter;
	GList *ps_iter;
	struct call_monologue *monologue;
	int sp_counter = 0;
	struct sdp_ng_flags flags;
	struct stream_params sp;
	int set = 0;

	memset(&flags, 0, sizeof(flags));
	memset(&sp, 0, sizeof(sp));

	__register_callid(redis, &call->callid);

	for (monologue_iter = call->monologues; monologue_iter; monologue_iter = monologue_iter->next) {
		monologue = monologue_iter->data;

		if (!set) {
			if (redis_insert_str_value_async(redis, &call->callid, "tt", &monologue->tag) < 0) {
				syslog(LOG_ERR, "couldn't insert ps counter into database\n");
				return;
			}

			if (monologue->active_dialogue && redis_insert_str_value_async(redis, &call->callid, "ft", &monologue->active_dialogue->tag) < 0) {
				syslog(LOG_ERR, "couldn't insert ps counter into database\n");
				return;
			}

			set = 1;
		}

		for (ml_media_iter = monologue->medias.head; ml_media_iter; ml_media_iter = ml_media_iter->next) {
			m = ml_media_iter->data;

			sp.index = m->index;
			sp.protocol = m->protocol;

			if (MEDIA_ISSET(m, RTCP_MUX))
				SP_SET((&sp), RTCP_MUX);

			sp.crypto = m->sdes_in.params;
			crypto_params_copy(&sp.crypto, &m->sdes_in.params, (flags.opmode == OP_OFFER) ? 1 : 0);
			sp.sdes_tag = m->sdes_in.tag;

			if (MEDIA_ISSET(m, ASYMMETRIC)) {
				SP_SET((&sp), ASYMMETRIC);
				flags.asymmetric = 1;
			}

			if (MEDIA_ISSET(m, SEND))
				SP_SET((&sp), SEND);

			if (MEDIA_ISSET(m, RECV))
				SP_SET((&sp), RECV);

			if (MEDIA_ISSET(m, SETUP_ACTIVE))
				SP_SET((&sp), SETUP_ACTIVE);

			if (MEDIA_ISSET(m, SETUP_PASSIVE))
				SP_SET((&sp), SETUP_PASSIVE);

			if (MEDIA_ISSET(m, ICE))
				SP_SET((&sp), ICE);

			sp.fingerprint = m->fingerprint;
			sp.desired_family = m->desired_family;
			// FIXME
			sp.consecutive_ports = 1;

//			SP_SET((&sp), IMPLICIT_RTCP);

			call_str_cpy(call, &sp.type, &m->type);
			memcpy(flags.direction, sp.direction, sizeof(sp.direction));
			flags.transport_protocol = m->protocol;

			SP_SET((&sp), NO_RTCP);

			for (ps_iter = m->streams.head; ps_iter; ps_iter = ps_iter->next) {
				ps = ps_iter->data;

				if (PS_ISSET(ps, RTCP)) {
					sp.rtcp_endpoint = ps->endpoint;
					SP_CLEAR((&sp), NO_RTCP);
				}
				else
					sp.rtp_endpoint = ps->endpoint;

				if (PS_ISSET(ps, IMPLICIT_RTCP))
					SP_SET((&sp), IMPLICIT_RTCP);

				if (PS_ISSET(ps, STRICT_SOURCE))
					SP_SET((&sp), STRICT_SOURCE);

				if (PS_ISSET(ps, MEDIA_HANDOVER))
					SP_SET((&sp), MEDIA_HANDOVER);
			}

			__insert_stream_params(redis, &call->callid, sp_counter++, &sp, ps->sfd->fd.localport);

			char buf[64];
			smart_ntop_p(buf, &sp.rtp_endpoint.ip46, sizeof(buf));
			syslog(LOG_INFO, "%s:%d", buf, sp.rtp_endpoint.port);
			smart_ntop_p(buf, &sp.rtcp_endpoint.ip46, sizeof(buf));
			syslog(LOG_INFO, "rtcp: %s:%d", buf, sp.rtcp_endpoint.port);
		}
	}

	if (redis_insert_int_value_async(redis, &call->callid, "master-lastport", call->callmaster->lastport) < 0) {
		syslog(LOG_ERR, "couldn't insert callmaster lastport into database\n");
		return;
	}

	// process async events
	event_base_loop(redis->eb, EVLOOP_NONBLOCK | EVLOOP_ONCE);
}

void mod_redis_delete(struct call *c, struct redis *redis) {
	syslog (LOG_INFO, __FUNCTION__);

	if (redis_remove_mp_entry(redis, &c->callid) < 0)
		syslog(LOG_ERR, "Error removing key from hash table\n");

	if (redis_remove_member(redis, &c->callid) < 0)
		syslog(LOG_ERR, "Error removing member from list\n");
}

int redis_remove_mp_entry(struct redis *redis, str *callid) {
	redisReply *rpl = NULL;
	char cmd_buffer[1024];
	int ret;

	snprintf(cmd_buffer, sizeof(cmd_buffer), "DEL mp:%.*s",callid->len, callid->s);

	ret = redis_exec(redis, cmd_buffer, &rpl);

	if (ret > 0)
		freeReplyObject(rpl);

	return ret;
}

void mod_redis_wipe(struct redis *r) {
	syslog (LOG_INFO, __FUNCTION__);
}

#ifdef obsolete_dtls
static int __restore_dtls_params(struct redis *redis, struct dtls_cert *cert) {
	int ret;
	str aux;
	const str default_hash_function = {"sha-1", sizeof("sha-1") - 1};

	ret = redis_restore_cert(redis, &cert->x509);
	if (ret < 0) {
		syslog(LOG_ERR, "error restoring certificate\n");
		return -1;
	}
	else if (ret == 0 && redis_insert_cert(redis, cert->x509) < 0) {
		syslog(LOG_ERR, "error inserting certificate\n");
		return -1;
	}
	else if (ret == 1)
		syslog(LOG_INFO, "certificate was restored from previous instance\n");

	ret = redis_restore_pkey(redis, &cert->pkey);
	if (ret < 0) {
		syslog(LOG_ERR, "error restoring pkey\n");
		return -1;
	}
	else if (ret == 0 && redis_insert_pkey(redis, cert->pkey) < 0) {
		syslog(LOG_ERR, "error inserting pkey\n");
		return -1;
	}
	else if (ret == 1)
		syslog(LOG_INFO, "pkey was restored from previous instance\n");

	ret = redis_restore_expires(redis, &cert->expires);
	if (ret < 0) {
		syslog(LOG_ERR, "error restoring expires\n");
		return -1;
	}
	else if (ret == 0 && redis_insert_expires(redis, &cert->expires) < 0) {
		syslog(LOG_ERR, "error inserting expires\n");
		return -1;
	}
	else if (ret == 1)
		syslog(LOG_INFO, "expires was restored from previous instance\n");

	cert->fingerprint.hash_func = dtls_find_hash_func(&default_hash_function);

	if (!cert->fingerprint.hash_func) {
		syslog(LOG_ERR, "error finding hash function\n");
		return -1;
	}

	ret = redis_restore_fingerprint(redis, &aux);
	if (ret < 0) {
		syslog(LOG_ERR, "error restoring fingerprint\n");
		return -1;
	}
	else if (ret == 0 && redis_insert_fingerprint(redis, cert->fingerprint.digest, sizeof(cert->fingerprint.digest)) < 0) {
		syslog(LOG_ERR, "error inserting fingerprint\n");
		return -1;
	}
	else if (ret == 1) {
		memcpy(cert->fingerprint.digest, aux.s, sizeof(cert->fingerprint.digest));
		g_free(aux.s);

		syslog(LOG_INFO, "fingerprint was restored from previous instance\n");
	}

	if (!X509_set_pubkey(cert->x509, cert->pkey))
		return -1;

	return 1;

/*	if (!X509_set_version(cert->x509, 0L))
		return -1;

	if (!X509_gmtime_adj(X509_get_notBefore(cert->x509), -60*60*24))
		return -1;

	if (!X509_gmtime_adj(X509_get_notAfter(cert->x509), (60*60*24*30)))
		return -1;
*/
	/* sign it */
//	if (!X509_sign(cert->x509, cert->pkey, EVP_sha1()))
//		return -1;

	//dtls_fingerprint_hash(&cert->fingerprint, cert->x509);

/*
	BIGNUM *exponent = NULL, *serial_number = NULL;
	RSA *rsa = NULL;
	ASN1_INTEGER *asn1_serial_number;
	X509_NAME *name;
	EVP_PKEY *pkey = NULL;

	pkey = EVP_PKEY_new();
	exponent = BN_new();
	rsa = RSA_new();
	serial_number = BN_new();
	name = X509_NAME_new();

	if (!BN_set_word(exponent, 0x10001))
		goto err;

	if (!RSA_generate_key_ex(rsa, 1024, exponent, NULL))
		goto err;

	if (!EVP_PKEY_assign_RSA(pkey, rsa))
		goto err;

	if (!X509_set_pubkey(cert->x509, pkey))
		goto err;

	if (!BN_pseudo_rand(serial_number, 64, 0, 0))
		goto err;

	asn1_serial_number = X509_get_serialNumber(cert->x509);
	if (!asn1_serial_number)
		goto err;

	if (!BN_to_ASN1_INTEGER(serial_number, asn1_serial_number))
		goto err;

	if (!X509_set_version(cert->x509, 0L))
		goto err;

	if (!X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8,
				(unsigned char *) "rtpengine", -1, -1, 0))
		goto err;

	if (!X509_set_subject_name(cert->x509, name))
		goto err;

	if (!X509_set_issuer_name(cert->x509, name))
		goto err;

	if (!X509_gmtime_adj(X509_get_notBefore(cert->x509), -60*60*24))
		goto err;

	if (!X509_gmtime_adj(X509_get_notAfter(cert->x509), (60*60*24*30)))
		goto err;

	if (!X509_sign(cert->x509, pkey, EVP_sha1()))
		goto err;

	//new_cert = obj_alloc0("dtls_cert", sizeof(*new_cert), cert_free);
	cert->fingerprint.hash_func = dtls_find_hash_func(&default_hash_function);
	dtls_fingerprint_hash(&cert->fingerprint, cert->x509);

	cert->pkey = pkey;

	return 1;
err:
	return -1;
*/
}
#endif

int mod_redis_restore(struct callmaster *cm, struct redis *redis) {
	str *list = NULL;
	str ft = {0,0};
	str tt = {0,0};
	str *callid = NULL;
	int length = 0;
	int i;
	struct stream_params sp1;
	struct stream_params sp2;
	struct sdp_ng_flags flags;
	uint16_t bridge_port1 = 0;
	uint16_t bridge_port2 = 0;

	syslog(LOG_INFO, __FUNCTION__);

#ifdef obsolete_dtls
	// get the certificate newly generated
	if (__restore_dtls_params(redis, dtls_cert()) < 0)
		return -1;
#endif

	if (__retrieve_call_list(redis, cm, &list, &length) < 0)
		return -1;

	for (i = 0; i < length; i++) {
		callid = &list[i];

		memset(&flags, 0, sizeof(flags));
		memset(&sp1, 0, sizeof(flags));
		memset(&sp2, 0, sizeof(flags));

		syslog(LOG_INFO, "Retrieve CID [%.*s]", callid->len, callid->s);

		// FIXME make stream id dynamic
		if (__retrieve_stream_params(redis, callid, 0, &sp1, &bridge_port1) < 0)
			goto next;

		// FIXME make stream id dynamic
		if (__retrieve_stream_params(redis, callid, 1, &sp2, &bridge_port2) < 0)
			goto next;

		syslog(LOG_INFO, "Retrieve bridge port 1 [%u] and 2 [%u]", bridge_port1, bridge_port2);

#ifdef obsolete_dtls
		syslog(LOG_INFO, "1 rtp %d rtcp %d fingerprint %p bp %d", sp1.rtp_endpoint.port, sp1.rtcp_endpoint.port, sp1.fingerprint.hash_func, bridge_port1);
		syslog(LOG_INFO, "2 rtp %d rtcp %d fingerprint %p bp %d", sp2.rtp_endpoint.port, sp2.rtcp_endpoint.port, sp2.fingerprint.hash_func,  bridge_port2);
		ZERO(sp1.fingerprint);
		ZERO(sp2.fingerprint);
#endif

		mutex_lock(&cm->hashlock);
		if (bridge_port1 > bridge_port2 && bridge_port2 > 0)
			cm->lastport = bridge_port2 - 1;
		else
			cm->lastport = bridge_port1 - 1;
		mutex_unlock(&cm->hashlock);

		if (bit_array_isset(cm->ports_used, cm->lastport)) {
			syslog(LOG_ERR, "Port #%d has already been used", cm->lastport);
			goto next;
		}

		sp1.index = 1;
		sp2.index = 1;

		__fill_flag(&flags, &sp1);

		// get call tags
		if (redis_get_str(redis, "HGET", callid, "ft", &ft) < 0)
			goto next;

		if (redis_get_str(redis, "HGET", callid, "tt", &tt) < 0)
			goto next;

		flags.opmode = OP_OFFER;
		if (__process_call(callid, cm, &sp1, &ft, NULL, &flags, OP_OFFER) < 0) {
			syslog(LOG_ERR, "error processing call [%.*s]\n", callid->len, callid->s);
			goto next;
		}

		memset(&flags, 0, sizeof(flags));

		__fill_flag(&flags, &sp2);

		flags.opmode = OP_ANSWER;
		if (__process_call(callid, cm, &sp2, &ft, &tt, &flags, OP_ANSWER) < 0) {
			syslog(LOG_ERR, "error processing call [%.*s]\n", callid->len, callid->s);
			goto next;
		}
next:
//		if (callid->s)
//			g_free(callid->s);
		;
	}
	//	if (list)
	//		g_free(list);
	return 0;
}

static void __fill_flag(struct sdp_ng_flags *flags, struct stream_params *sp) {
	flags->address_family = sp->desired_family;
	flags->transport_protocol = sp->protocol;

	if (SP_ISSET(sp, ASYMMETRIC))
		flags->asymmetric = 1;

	if (SP_ISSET(sp, STRICT_SOURCE))
		flags->strict_source = 1;

	if (SP_ISSET(sp, MEDIA_HANDOVER))
		flags->media_handover = 1;
}

static int __process_call(str *callid, struct callmaster *cm, struct stream_params *sp,
		str *ft, str *tt, struct sdp_ng_flags *flags, enum call_opmode op_mode) {

	struct call *call = NULL;
	GQueue streams = G_QUEUE_INIT;
	struct call_monologue *monologue = NULL;

	if (!(call = call_get_opmode(callid, cm, op_mode))) {
		syslog(LOG_ERR, "error obtaining call using op_mode=%d\n", op_mode);
		goto error;
	}

	if (!(monologue = call_get_mono_dialogue(call, ft, tt, NULL))) {
		syslog(LOG_ERR, "error allocating monologue\n");
		goto error;
	}

	g_queue_push_tail(&streams, sp);

	if (monologue_offer_answer(monologue, &streams, flags) < 0) {
		syslog(LOG_ERR, "error processing monologue\n");
		goto error;
	}

	rwlock_unlock_w(&call->master_lock);
	obj_put(call);

//	__streams_free(&streams);

	return 1;
error:
	if (call)
		rwlock_unlock_w(&call->master_lock);

	return-1;
}

struct redis *mod_redis_new(struct in_addr ip, u_int16_t port, int db) {
	return redis_connect(ip, port, db);
}

#ifdef obsolete_dtls
static void __dtls_connection_init(struct packet_stream *ps, struct dtls_cert *cert) {
	char *p;
	char *ciphers_str;
	int i;
	struct dtls_connection *d = &ps->sfd->dtls;

	p = ciphers_str;
	for (i = 0; i < num_crypto_suites; i++) {
		if (!crypto_suites[i].dtls_name)
			continue;
		p += sprintf(p, "%s:", crypto_suites[i].dtls_name);
	}

	p[-1] = '\0';

	//d->ssl_ctx = SSL_CTX_new(active ? DTLSv1_client_method() : DTLSv1_server_method());
	d->ssl_ctx = SSL_CTX_new(DTLSv1_client_method());
	if (!d->ssl_ctx)
		goto error;

	if (SSL_CTX_use_certificate(d->ssl_ctx, cert->x509) != 1)
		goto error;
	if (SSL_CTX_use_PrivateKey(d->ssl_ctx, cert->pkey) != 1)
		goto error;

//	SSL_CTX_set_verify(d->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
//			verify_callback);
	SSL_CTX_set_verify_depth(d->ssl_ctx, 4);
	SSL_CTX_set_cipher_list(d->ssl_ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");

	if (SSL_CTX_set_tlsext_use_srtp(d->ssl_ctx, ciphers_str))
		goto error;

	d->ssl = SSL_new(d->ssl_ctx);
	if (!d->ssl)
		goto error;

	d->r_bio = BIO_new(BIO_s_mem());
	d->w_bio = BIO_new(BIO_s_mem());
	if (!d->r_bio || !d->w_bio)
		goto error;

	SSL_set_app_data(d->ssl, ps->sfd); /* XXX obj reference here? */
	SSL_set_bio(d->ssl, d->r_bio, d->w_bio);
	SSL_set_mode(d->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	d->init = 1;
	d->active = 1;

error:
	syslog(LOG_ERR, "error");
	return;
}
#endif

static void __streams_free(GQueue *q) {
	struct stream_params *s;

	while ((s = g_queue_pop_head(q))) {
		if (s->crypto.mki)
			free(s->crypto.mki);
		g_slice_free1(sizeof(*s), s);
	}
}

#define VAL_SIZE(_x_) (char *)&(_x_), sizeof((_x_))

static int __retrieve_call_list(struct redis *redis, struct callmaster *cm, str **list, int *length) {
	redisReply *rpl = NULL;
	int j;

	if (redis_exec(redis, "SMEMBERS mp:calls", &rpl) < 0)
		return -1;

	if (!rpl || rpl->type == REDIS_REPLY_ERROR) {
		if (!rpl)
			syslog(LOG_ERR, "%s", redis->ctxt->errstr);
		else {
			syslog(LOG_ERR, "%.*s", rpl->len, rpl->str);
			freeReplyObject(rpl);
		}

		// reconnect on error
		redis_connect_all(redis);
		return -1;
	}

	if (rpl->elements <= 0) {
		syslog(LOG_INFO, "array is empty\n");
		*length = 0;
		return 1;
	}

	*list = g_malloc0(sizeof(str) * rpl->elements);
	*length = rpl->elements;

	for (j = 0; j < rpl->elements; j++) {

		if (rpl->element[j]->len <= 0) {
			syslog(LOG_ERROR,"array entry is empty\n");
			continue;
		}

		(*list)[j].s = g_malloc0(rpl->element[j]->len);
		(*list)[j].len = rpl->element[j]->len;

		memcpy((*list)[j].s, rpl->element[j]->str, (*list)[j].len);
	}

	freeReplyObject(rpl);

	return 1;
}

static const char *__crypto_find_name(const struct crypto_suite *ptr) {
	int i;
	const struct crypto_suite *cs;

	for (i = 0; i < num_crypto_suites; i++) {
			cs = &crypto_suites[i];

			if (cs == ptr)
				return cs->name;
	}

	return NULL;
}

static void __print_flags(const char *title, struct stream_params *sp) {

	syslog(LOG_ERR, "====> %s", title);

	syslog(LOG_ERR, "NO_RTCP %d", SP_ISSET(sp, NO_RTCP));
	syslog(LOG_ERR, "IMPLICIT_RTCP %d", SP_ISSET(sp, IMPLICIT_RTCP));
	syslog(LOG_ERR, "SEND %d", SP_ISSET(sp, SEND));
	syslog(LOG_ERR, "RECV %d", SP_ISSET(sp, RECV));
	syslog(LOG_ERR, "ASYMMETRIC %d", SP_ISSET(sp, ASYMMETRIC));
	syslog(LOG_ERR, "RTCP_MUX %d", SP_ISSET(sp, RTCP_MUX));
	syslog(LOG_ERR, "SETUP_ACTIVE %d", SP_ISSET(sp, SETUP_ACTIVE));
	syslog(LOG_ERR, "SETUP_PASSIVE %d", SP_ISSET(sp, SETUP_PASSIVE));
	syslog(LOG_ERR, "ICE %d", SP_ISSET(sp, ICE));
	syslog(LOG_ERR, "STRICT_SOURCE %d", SP_ISSET(sp, STRICT_SOURCE));
	syslog(LOG_ERR, "MEDIA_HANDOVER %d", SP_ISSET(sp, MEDIA_HANDOVER));

}

static int __retrieve_stream_params(struct redis *redis, str* callid, int stream_id, struct stream_params *sp, uint16_t *bridge_port) {
	int aux_int = 0;
	char key[128], val[128];
	str aux;
	//const char *crypto_name = NULL;

	memset(val, 0, sizeof(val));
	memset(sp, 0, sizeof(*sp));

	snprintf(key, sizeof(key), "%d:flags", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(&sp->sp_flags, aux);

//	print_flags("retrieved", sp);
	//PS_CLEAR(sp, HAS_HANDLER);
	//PS_CLEAR(sp, KERNELIZED);

	snprintf(key, sizeof(key), "%d:bridge_port", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	syslog(LOG_INFO,"Retrieved Bridge Port ascii:%s",aux);

	if (aux.len != 2) {
		syslog(LOG_ERROR,"bridge port retrieved but length is (not 2):%u", aux.len);
		goto  error;
	}

	COPY_AND_FREE(bridge_port, aux);

	syslog(LOG_INFO,"Retrieved Bridge Port:%u",*bridge_port);


	snprintf(key, sizeof(key), "%d:index", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(&sp->index, aux);

	// fingerprint setup for dtls
	snprintf(key, sizeof(key), "%d:fingerprint-digest", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(sp->fingerprint.digest, aux);

	snprintf(key, sizeof(key), "%d:fingerprint-name", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	if (aux.s) {
		sp->fingerprint.hash_func = dtls_find_hash_func(&aux);

		if (!sp->fingerprint.hash_func) {
			syslog(LOG_ERR, "couldn't find dtls hash function using [%.*s]", aux.len, aux.s);
			g_free(aux.s);
			goto error;
		}

		g_free(aux.s);
	}

	// crypto setup for SDES
	snprintf(key, sizeof(key), "%d:crypto-name", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	if (aux.s) {
		sp->crypto.crypto_suite = crypto_find_suite(&aux);

		if (!sp->crypto.crypto_suite) {
			syslog(LOG_ERR, "couldn't find crypto suite using [%.*s]", aux.len, aux.s);
			g_free(aux.s);
			goto error;
		}

		g_free(aux.s);
	}

	snprintf(key, sizeof(key), "%d:crypto-key", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	if (aux.len > sizeof(sp->crypto.master_key)) {
		syslog(LOG_ERR, "length is greater than master key max length\n");
		goto error;
	}

	COPY_AND_FREE(sp->crypto.master_key, aux);

	snprintf(key, sizeof(key), "%d:crypto-salt", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	if (aux.len > sizeof(sp->crypto.master_salt)) {
		syslog(LOG_ERR, "length is greater than master salt max length\n");
		goto error;
	}

	COPY_AND_FREE(sp->crypto.master_salt, aux);

	snprintf(key, sizeof(key), "%d:crypto-mki", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(sp->crypto.mki, aux);

	snprintf(key, sizeof(key), "%d:crypto-mki-len", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(&sp->crypto.mki_len, aux);

	if ((sp->crypto.mki_len > 0 && !sp->crypto.mki) ||
		(sp->crypto.mki_len == 0 && sp->crypto.mki)) {
		syslog(LOG_ERR, "couldn't retrieve mki\n");
		goto error;
	}

	snprintf(key, sizeof(key), "%d:type", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &sp->type) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:stream_direction",  stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(&sp->direction, aux);
	//memcpy(&sp->direction, aux.s, aux.len);

	snprintf(key, sizeof(key), "%d:desired_family", stream_id);
	if (redis_get_int(redis, "HGET", callid, key, &sp->desired_family) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:transport-index", stream_id);
	if (redis_get_int(redis, "HGET", callid, key, &aux_int) < 0)
		goto error;

	sp->protocol = &transport_protocols[aux_int];
	//sp->protocol->name = transport_protocols[]
	//sp->protocol->index;

	syslog(LOG_ERR, "---> %s | %s %s", sp->protocol->name, sp->protocol->srtp ? "y" : "n", sp->protocol->avpf ? "y" : "n");

	snprintf(key, sizeof(key), "%d:sdes-tag", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(&sp->sdes_tag, aux);

	snprintf(key, sizeof(key), "%d:rtp_endpoint",  stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(&sp->rtp_endpoint, aux);

	snprintf(key, sizeof(key), "%d:rtcp_endpoint", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(&sp->rtcp_endpoint, aux);

	snprintf(key, sizeof(key), "%d:consecutive_ports", stream_id);
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	COPY_AND_FREE(&sp->consecutive_ports, aux);

	return 1;
error:
	return -1;

}

static int __insert_stream_params(struct redis *redis, str* callid, int stream_id, struct stream_params *sp, uint16_t bridge_port) {
	char key[128];
	const char *crypto_name = __crypto_find_name(sp->crypto.crypto_suite);

	snprintf(key, sizeof(key), "%d:flags", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, &sp->sp_flags, sizeof(sp->sp_flags)) < 0)
		goto error;

	syslog(LOG_INFO,"Bridge Port:%u",bridge_port);

	snprintf(key, sizeof(key), "%d:bridge_port", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(bridge_port)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:index", stream_id);
	if (redis_insert_int_value_async(redis, callid, key, sp->index) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:fingerprint-digest", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, sp->fingerprint.digest, sizeof(sp->fingerprint.digest)) < 0)
		goto error;

	if (sp->fingerprint.hash_func) {
		snprintf(key, sizeof(key), "%d:fingerprint-name", stream_id);
		if (redis_insert_bin_value_async(redis, callid, key, sp->fingerprint.hash_func->name, strlen(sp->fingerprint.hash_func->name)) < 0)
			goto error;
	}

	if (crypto_name) {
		snprintf(key, sizeof(key), "%d:crypto-name", stream_id);
		if (redis_insert_bin_value_async(redis, callid, key, crypto_name, strlen(crypto_name)) < 0)
			goto error;
	}

	snprintf(key, sizeof(key), "%d:crypto-key", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, sp->crypto.master_key, sizeof(sp->crypto.master_key)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:crypto-salt", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, sp->crypto.master_salt, sizeof(sp->crypto.master_salt)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:crypto-mki", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, sp->crypto.mki, sp->crypto.mki_len) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:crypto-mki-len", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->crypto.mki_len)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:type", stream_id);
	if (redis_insert_str_value_async(redis, callid, key, &sp->type) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:stream_direction",  stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->direction)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:desired_family", stream_id);
	if (redis_insert_int_value_async(redis, callid, key, sp->desired_family) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:transport-index", stream_id);
	if (redis_insert_int_value_async(redis, callid, key, sp->protocol->index) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:sdes-tag", stream_id);
	if (redis_insert_int_value_async(redis, callid, key, sp->sdes_tag) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:rtp_endpoint",  stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->rtp_endpoint)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:rtcp_endpoint", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->rtcp_endpoint)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:consecutive_ports", stream_id);
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->consecutive_ports)) < 0)
		goto error;

	return 1;
error:
	return -1;
}

static int __register_callid(struct redis *redis, str* callid) {
	redisReply *rpl;
	char buff[CMD_BUFFER_SIZE];
	snprintf(buff, sizeof(buff), "SADD mp:calls %.*s", callid->len, callid->s);

	if (redis_exec(redis, buff, &rpl) > 0)
		freeReplyObject(rpl);

	return 1;
}
