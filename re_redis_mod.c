#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>

#include "./rtpengine/daemon/sdp.h"
#include "./rtpengine/daemon/call.h"
#include "re_redis_mod.h"
#include "redis_storage.h"

char *__module_version = "redis/9";

#define DECL_STRUCT_SIZE(_s_) unsigned long __size_struct_ ## _s_ = sizeof(struct _s_);

#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)
#define MEMBER_OFFSET(type, member) &(((type *)0)->member)

#define DECL_MEMBER_OFFSET(_s_, _m_) unsigned long __offset_struct_ ## _s_ ## _ ## _m_ =  (unsigned long) MEMBER_OFFSET(struct _s_, _m_);
#define DECL_MEMBER_SIZE(_s_, _m_) unsigned long __size_struct_ ## _s_ ## _ ## _m_ = MEMBER_SIZE(struct _s_, _m_);
#define DECL_MEMBER_OFFSET_SIZE(_s_, _m_) DECL_MEMBER_OFFSET(_s_, _m_) \
                                          DECL_MEMBER_SIZE(_s_, _m_)

/* REDIS call keys */
#define CALL_TT_KEY				0
#define CALL_FT_KEY				1
#define CALL_LASTPORT_KEY			2
#define CALL_TOS_KEY				3
#define CALL_STREAM_COUNT_KEY			4
#define CALL_CREATED_FROM_KEY			5
#define CALL_MAX_KEY				6

/* REDIS stream keys */
#define STREAM_PAYLOAD_TYPE_KEY			0
#define STREAM_PAYLOAD_COUNT_KEY		1
#define STREAM_FLAGS_KEY			2
#define STREAM_RTP_BRIDGE_PORT_KEY		3
#define STREAM_RTCP_BRIDGE_PORT_KEY		4
#define STREAM_INDEX_KEY			5
#define STREAM_FINGER_DIGEST_KEY		6
#define STREAM_FINGER_NAME_KEY			7
#define STREAM_CRYPTO_NAME_KEY			8
#define STREAM_CRYPTO_KEY			9
#define STREAM_CRYPTO_SALT_KEY			10
#define STREAM_CRYPTO_MKI_KEY			11
#define STREAM_CRYPTO_MKI_LEN_KEY		12
#define STREAM_TYPE_KEY				13
#define STREAM_DIRECTION_KEY			14
#define STREAM_FAMILY_KEY			15
#define STREAM_TRANSPORT_KEY			16
#define STREAM_SDES_KEY				17
#define STREAM_RTP_ENDPOINT_KEY			18
#define STREAM_RTCP_ENDPOINT_KEY		19
#define STREAM_CONSECUTIVE_PORTS_KEY		20
#define STREAM_MAX_KEY				21

/* REDIS call key array */
const char *redis_call_keys[CALL_MAX_KEY] = {
	"tt",
	"ft",
	"lastport",
	"tos",
	"stream-count",
	"created-from",
};

/* REDIS stream key array */
const char *redis_stream_keys[STREAM_MAX_KEY] = {
	"payload-type",
	"payload-count",
	"flags",
	"rtp-bridge-port",
	"rtcp-bridge-port",
	"index",
	"fingerprint-digest",
	"fingerprint-name",
	"crypto-name",
	"crypto-key",
	"crypto-salt",
	"crypto-mki",
	"crypto-mki-len",
	"type",
	"stream_direction",
	"desired_family",
	"transport-index",
	"sdes-tag",
	"rtp-endpoint",
	"rtcp-endpoint",
	"consecutive_ports",
};

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

//static void __streams_free(GQueue *q);
static void __print_flags(const char *title, struct stream_params *sp);

static int __insert_stream_params(struct redis *redis, str* callid, int stream_id,
	struct stream_params *sp, unsigned int rtp_bridge_port, unsigned int rtcp_bridge_port);
static int __retrieve_stream_params(struct redis *redis, str* callid, int stream_id,
	struct stream_params *sp, unsigned int *rtp_bridge_port, unsigned int *rtcp_bridge_port);
static int __register_callid(struct redis *redis, str* callid);
static int __retrieve_call_list(struct redis *redis, struct callmaster *cm, str **list, int *length);
static const char *__crypto_find_name(const struct crypto_suite *ptr);
static int __process_call(str *callid, struct callmaster *cm, struct stream_params *sp, str *ft, str *tt, str *proxy, struct sdp_ng_flags *flags, enum call_opmode op_mode,
	unsigned int *rtp_bridge_ports, unsigned int *rtcp_bridge_ports, unsigned int stream_count);
static void __fill_flag(struct sdp_ng_flags *flags, struct stream_params *sp);

static const char* redis_get_call_key(unsigned int key) {
	if (key >= CALL_MAX_KEY) {
		return NULL;
	}

	return redis_call_keys[key];
}

static const char* redis_get_stream_key(unsigned int key) {
	if (key >= STREAM_MAX_KEY) {
		return NULL;
	}

	return redis_stream_keys[key];
}

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
	unsigned int rtp_bridge_port = 0, rtcp_bridge_port = 0;
	struct rtp_payload_type *pt;
	GList *values, *iter;
	str proxy = {0,0};

	memset(&flags, 0, sizeof(flags));
	memset(&sp, 0, sizeof(sp));

	__register_callid(redis, &call->callid);

	for (monologue_iter = call->monologues; monologue_iter; monologue_iter = monologue_iter->next) {
		monologue = monologue_iter->data;

		if (!set) {
			if (redis_insert_str_value_async(redis, &call->callid, redis_get_call_key(CALL_TT_KEY), &monologue->tag) < 0) {
				plog(LOG_ERR, "couldn't insert ps counter into database\n");
				return;
			}

			if (monologue->active_dialogue && redis_insert_str_value_async(redis, &call->callid,  redis_get_call_key(CALL_FT_KEY), &monologue->active_dialogue->tag) < 0) {
				plog(LOG_ERR, "couldn't insert ps counter into database\n");
				return;
			}

			set = 1;
		}

		for (ml_media_iter = monologue->medias.head; ml_media_iter; ml_media_iter = ml_media_iter->next) {
			m = ml_media_iter->data;

			// push payload types in temporary sp structure which will be written into redis database
			values = g_hash_table_get_values(m->rtp_payload_types);
			for (iter = values; iter; iter = iter->next) {
				pt = iter->data;
				g_queue_push_tail(&sp.rtp_payload_types, pt);
				plog(LOG_DEBUG, "insert payload_type = %d", pt->payload_type);
			}
			g_list_free(values);

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
					rtcp_bridge_port = ps->sfd->fd.localport;
					sp.rtcp_endpoint = ps->endpoint;
					SP_CLEAR((&sp), NO_RTCP);
				}
				else {
					rtp_bridge_port = ps->sfd->fd.localport;
					sp.rtp_endpoint = ps->endpoint;
				}

				if (PS_ISSET(ps, IMPLICIT_RTCP))
					SP_SET((&sp), IMPLICIT_RTCP);

				if (PS_ISSET(ps, STRICT_SOURCE))
					SP_SET((&sp), STRICT_SOURCE);

				if (PS_ISSET(ps, MEDIA_HANDOVER))
					SP_SET((&sp), MEDIA_HANDOVER);
			}

			// the OFFER streams are inserted firstly and the ANSWER streams are inserted lastly in the database
			// this is the behaviour due to rtpengine's call_offer_answer_ng()
			__insert_stream_params(redis, &call->callid, sp_counter++, &sp, rtp_bridge_port, rtcp_bridge_port);

			char buf[64];
			smart_ntop_p(buf, &sp.rtp_endpoint.ip46, sizeof(buf));
			plog(LOG_DEBUG, "RTP: %s:%d", buf, sp.rtp_endpoint.port);
			smart_ntop_p(buf, &sp.rtcp_endpoint.ip46, sizeof(buf));
			plog(LOG_DEBUG, "RTCP: %s:%d", buf, sp.rtcp_endpoint.port);
		}
	}

	if (redis_insert_int_value_async(redis, &call->callid, redis_get_call_key(CALL_LASTPORT_KEY), call->callmaster->lastport) < 0) {
		plog(LOG_ERR, "couldn't insert callmaster lastport into database\n");
		return;
	}

	if (redis_insert_int_value_async(redis, &call->callid, redis_get_call_key(CALL_STREAM_COUNT_KEY), sp_counter) < 0) {
		plog(LOG_ERR, "couldn't insert streams count into database\n");
		return;
	}

	// keep call tos in order to fill flags.tos when redis restore
	if (redis_insert_uint_value_async(redis, &call->callid, redis_get_call_key(CALL_TOS_KEY), call->tos) < 0) {
		plog(LOG_ERR, "couldn't insert callmaster lastport into database\n");
		return;
	}

	// keep call created_from to identify details about control proxy
	proxy.s = call->created_from;
	proxy.len = strlen(call->created_from);
	if (redis_insert_str_value_async(redis, &call->callid, redis_get_call_key(CALL_CREATED_FROM_KEY), &proxy) < 0) {
		plog(LOG_ERR, "couldn't insert proxy string into database\n");
		return;
	}

	// process async events
	event_base_loop(redis->eb, EVLOOP_NONBLOCK | EVLOOP_ONCE);
}

void mod_redis_delete(struct call *c, struct redis *redis) {
	if (redis_remove_mp_entry(redis, &c->callid) < 0)
		plog(LOG_ERR, "Error removing key from hash table\n");

	if (redis_remove_member(redis, &c->callid) < 0)
		plog(LOG_ERR, "Error removing member from list\n");
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
}

#ifdef obsolete_dtls
static int __restore_dtls_params(struct redis *redis, struct dtls_cert *cert) {
	int ret;
	str aux;
	const str default_hash_function = {"sha-1", sizeof("sha-1") - 1};

	ret = redis_restore_cert(redis, &cert->x509);
	if (ret < 0) {
		plog(LOG_ERR, "error restoring certificate\n");
		return -1;
	}
	else if (ret == 0 && redis_insert_cert(redis, cert->x509) < 0) {
		plog(LOG_ERR, "error inserting certificate\n");
		return -1;
	}
	else if (ret == 1)
		plog(LOG_INFO, "certificate was restored from previous instance\n");

	ret = redis_restore_pkey(redis, &cert->pkey);
	if (ret < 0) {
		plog(LOG_ERR, "error restoring pkey\n");
		return -1;
	}
	else if (ret == 0 && redis_insert_pkey(redis, cert->pkey) < 0) {
		plog(LOG_ERR, "error inserting pkey\n");
		return -1;
	}
	else if (ret == 1)
		plog(LOG_INFO, "pkey was restored from previous instance\n");

	ret = redis_restore_expires(redis, &cert->expires);
	if (ret < 0) {
		plog(LOG_ERR, "error restoring expires\n");
		return -1;
	}
	else if (ret == 0 && redis_insert_expires(redis, &cert->expires) < 0) {
		plog(LOG_ERR, "error inserting expires\n");
		return -1;
	}
	else if (ret == 1)
		plog(LOG_INFO, "expires was restored from previous instance\n");

	cert->fingerprint.hash_func = dtls_find_hash_func(&default_hash_function);

	if (!cert->fingerprint.hash_func) {
		plog(LOG_ERR, "error finding hash function\n");
		return -1;
	}

	ret = redis_restore_fingerprint(redis, &aux);
	if (ret < 0) {
		plog(LOG_ERR, "error restoring fingerprint\n");
		return -1;
	}
	else if (ret == 0 && redis_insert_fingerprint(redis, cert->fingerprint.digest, sizeof(cert->fingerprint.digest)) < 0) {
		plog(LOG_ERR, "error inserting fingerprint\n");
		return -1;
	}
	else if (ret == 1) {
		memcpy(cert->fingerprint.digest, aux.s, sizeof(cert->fingerprint.digest));
		g_free(aux.s);

		plog(LOG_INFO, "fingerprint was restored from previous instance\n");
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
mod_redis_restore
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

/* substitutes the first half with the second half of the array */
static void swap_bridgeports(unsigned int *rtp_bridge_ports, unsigned int len) {
	unsigned int iter;
	unsigned int aux;

	for (iter = 0; iter < len / 2; iter++) {
		aux = rtp_bridge_ports[iter];
		rtp_bridge_ports[iter] = rtp_bridge_ports[iter + len / 2];
		rtp_bridge_ports[iter + len / 2] = aux;
	}
}

int mod_redis_restore(struct callmaster *cm, struct redis *redis) {
	str *list = NULL;
	str ft = {0,0};
	str tt = {0,0};
	str proxy = {0,0};
	str *callid = NULL;
	int length = 0, stream_count = 0, stream_iter = 0;
	int i;
	unsigned int tos = 0;

	// useful arrays
	struct stream_params *sp;
	struct sdp_ng_flags *flags;
	unsigned int *rtp_bridge_ports;
	unsigned int *rtcp_bridge_ports;

#ifdef obsolete_dtls
	// get the certificate newly generated
	if (__restore_dtls_params(redis, dtls_cert()) < 0)
		return -1;
#endif

	// get list of calls
	if (__retrieve_call_list(redis, cm, &list, &length) < 0)
		return -1;

	for (i = 0; i < length; i++) {
		// get call
		callid = &list[i];
		plog(LOG_INFO, "Retrieve call ID [%.*s]", callid->len, callid->s);

		// get call from tag
		if (redis_get_str(redis, "HGET", callid, redis_get_call_key(CALL_FT_KEY), &ft) < 0)
			goto next;
		plog(LOG_INFO, "Retrieve call %s [%.*s]", redis_get_call_key(CALL_FT_KEY), ft.len, ft.s);

		// get call to tag
		if (redis_get_str(redis, "HGET", callid, redis_get_call_key(CALL_TT_KEY), &tt) < 0)
			goto next;
		plog(LOG_INFO, "Retrieve call %s [%.*s]", redis_get_call_key(CALL_TT_KEY), tt.len, tt.s);

		// get call tos
		if (redis_get_uint(redis, "HGET", callid, redis_get_call_key(CALL_TOS_KEY), &tos) < 0)
			goto next;
		plog(LOG_INFO, "Retrieve call %s [%u]", redis_get_call_key(CALL_TOS_KEY), tos);

		// get call control proxy
		if (redis_get_str(redis, "HGET", callid, redis_get_call_key(CALL_CREATED_FROM_KEY), &proxy) < 0)
			goto next;
		plog(LOG_INFO, "Retrieve call %s [%.*s]", redis_get_call_key(CALL_CREATED_FROM_KEY), proxy.len, proxy.s);

		// get number of stream params; 2 for audio only, 4 for audio + video
		if ((redis_get_int(redis, "HGET", callid, redis_get_call_key(CALL_STREAM_COUNT_KEY), &stream_count) < 0) || (stream_count % 2))
			goto next;
		plog(LOG_INFO, "Retrieve call %s [%u]", redis_get_call_key(CALL_STREAM_COUNT_KEY), stream_count);

		// alloc stream params and bridgeport vector
		sp = (struct stream_params *) calloc (stream_count, sizeof(struct stream_params));
		flags = (struct sdp_ng_flags *) calloc (stream_count, sizeof(struct sdp_ng_flags));
		rtp_bridge_ports = (unsigned int *) calloc (stream_count, sizeof(unsigned int));
		rtcp_bridge_ports = (unsigned int *) calloc (stream_count, sizeof(unsigned int));

		// retrieve call stream params and r(c)tp bridgeports
		// due to insertion order, the OFFER stream params are retrieved first and the ANSWER last
		for (stream_iter = 0; stream_iter < stream_count; stream_iter++) {
			if (__retrieve_stream_params(redis, callid, stream_iter, &sp[stream_iter], &rtp_bridge_ports[stream_iter], &rtcp_bridge_ports[stream_iter]) < 0)
					goto next;

			plog(LOG_INFO, "Retrieve rtp bridge port [%u], rtcp bridge port [%u]",
				rtp_bridge_ports[stream_iter], rtcp_bridge_ports[stream_iter]);
#ifdef obsolete_dtls
			plog(LOG_INFO, "%d rtp %d rtcp %d fingerprint %p bp %d", stream_iter, sp[stream_iter].rtp_endpoint.port, sp[stream_iter].rtcp_endpoint.port,
				sp[stream_iter].fingerprint.hash_func, rtp_bridge_ports[stream_iter]);
			ZERO(sp[stream_iter].fingerprint);
#endif
			sp[stream_iter].index = 1;

			// only the OFFER and ANSWER flags are needed but we keep per stream_params flags
			__fill_flag(&flags[stream_iter], &sp[stream_iter]);
			flags[stream_iter].tos = tos;
			if (stream_iter % 2 == 0) {
				flags[stream_iter].opmode = OP_OFFER;
			} else {
				flags[stream_iter].opmode = OP_ANSWER;
			}
		}

		// switch the first half of the bridgeports with the second half
		// this is necessary due to rtpengine commit 16b42fbd62d930f8a38283c5086fe7ac026e80e6 which swaps the OFFER/ANSWER stream logic
		swap_bridgeports(rtp_bridge_ports, stream_count);
		swap_bridgeports(rtcp_bridge_ports, stream_count);

		// process offer
		if (__process_call(callid, cm, sp, &ft, NULL, &proxy, flags, OP_OFFER, rtp_bridge_ports, rtcp_bridge_ports, stream_count) < 0) {
			plog(LOG_ERR, "error processing call [%.*s]\n", callid->len, callid->s);
			goto next;
		}

		// process answer
		if (__process_call(callid, cm, sp, &ft, &tt, &proxy, flags, OP_ANSWER, rtp_bridge_ports, rtcp_bridge_ports, stream_count) < 0) {
			plog(LOG_ERR, "error processing call [%.*s]\n", callid->len, callid->s);
			goto next;
		}
next:
//		if (callid->s)
//			g_free(callid->s);
		;
		// TODO: don't like this alloc and free; maybe in the future we make static like sp[8] => 4 media per call
		free(sp);
		free(flags);
		free(rtp_bridge_ports);
		free(rtcp_bridge_ports);
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
		str *ft, str *tt, str *proxy, struct sdp_ng_flags *flags, enum call_opmode op_mode,
		unsigned int *rtp_bridge_ports, unsigned int *rtcp_bridge_ports, unsigned int stream_count) {

	unsigned int stream_iter = 0;
	struct call *call = NULL;
	GQueue streams = G_QUEUE_INIT;
	struct call_monologue *monologue = NULL;

	if (!(call = call_get_opmode(callid, cm, op_mode))) {
		plog(LOG_ERR, "error obtaining call using op_mode=%d\n", op_mode);
		goto error;
	}

	// keep control proxy info
	call->created_from = call_strdup_len(call, proxy->s, proxy->len);

	// clear the bridgeports queue
	g_queue_clear(&call->rtp_bridge_ports);

	switch (op_mode) {
		case OP_OFFER:
			// get/create monologue
			if (!(monologue = call_get_mono_dialogue(call, ft, tt, NULL))) {
				plog(LOG_ERR, "error allocating monologue\n");
				goto error;
			}

			// fix the tag-type displayed at "rtpengine-ctl sessions"
			monologue->tagtype = FROM_TAG;

			// add the OFFER stream params present in the first half of the sp array (e.g. sp1, sp2)
			// push the correspondent bridge ports (e.g [sp1_bp, sp3_bp], [sp2_bp, sp4_bp])
			for (stream_iter = 0; stream_iter < stream_count / 2; stream_iter++) {
				g_queue_push_tail(&streams, &sp[stream_iter]);
				g_queue_push_tail(&call->rtp_bridge_ports, GUINT_TO_POINTER(rtp_bridge_ports[stream_iter]));
				g_queue_push_tail(&call->rtp_bridge_ports, GUINT_TO_POINTER(rtp_bridge_ports[stream_iter + stream_count / 2]));
			}

			// call rtpengine main logic with OFFER flags
			if (monologue_offer_answer(monologue, &streams, &flags[stream_count / 2 - 1]) < 0) {
				plog(LOG_ERR, "error processing monologue\n");
				goto error;
			}

			break;

		case OP_ANSWER:
			// fix the call_get_mono_dialogue() for 4.1 (this is not needed for 4.0 or 3.3.0)
			// -> see also call_offer_answer_ng()->str_swap() in rtpengine's call_interfaces.c
			str_swap(tt, ft);

			// get/create monologue
			if (!(monologue = call_get_mono_dialogue(call, ft, tt, NULL))) {
				plog(LOG_ERR, "error allocating monologue\n");
				goto error;
			}

			// fix the tag-type displayed at "rtpengine-ctl sessions"
			monologue->tagtype = TO_TAG;

			// add the ANSWER stream params present in the second half of the sp array (e.g. sp3, sp4)
			// no bridge ports needed (were allocated at the OFFER)
			for (stream_iter = stream_count / 2; stream_iter < stream_count; stream_iter++) {
				g_queue_push_tail(&streams, &sp[stream_iter]);
			}

			// call rtpengine main logic with ANSWER flags
			if (monologue_offer_answer(monologue, &streams, &flags[stream_count / 2]) < 0) {
				plog(LOG_ERR, "error processing monologue\n");
				goto error;
			}

			break;

		default:
			plog(LOG_ERR, "op_mode %d not found; need either OP_OFFER or OP_ANSWER\n", op_mode);
			break;
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
	plog(LOG_ERR, "error");
	return;
}
#endif

/*
static void __streams_free(GQueue *q) {
	struct stream_params *s;

	while ((s = g_queue_pop_head(q))) {
		if (s->crypto.mki)
			free(s->crypto.mki);
		g_slice_free1(sizeof(*s), s);
	}
}
*/

#define VAL_SIZE(_x_) (char *)&(_x_), sizeof((_x_))

static int __retrieve_call_list(struct redis *redis, struct callmaster *cm, str **list, int *length) {
	redisReply *rpl = NULL;
	int j;

	if (redis_exec(redis, "SMEMBERS mp:calls", &rpl) < 0)
		return -1;

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

	if (rpl->elements <= 0) {
		plog(LOG_INFO, "array is empty\n");
		*length = 0;
		return 1;
	}

	*list = g_malloc0(sizeof(str) * rpl->elements);
	*length = rpl->elements;

	for (j = 0; j < rpl->elements; j++) {

		if (rpl->element[j]->len <= 0) {
			plog(LOG_ERROR,"array entry is empty\n");
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

	plog(LOG_DEBUG, "====> %s", title);

	plog(LOG_DEBUG, "NO_RTCP %d", SP_ISSET(sp, NO_RTCP));
	plog(LOG_DEBUG, "IMPLICIT_RTCP %d", SP_ISSET(sp, IMPLICIT_RTCP));
	plog(LOG_DEBUG, "SEND %d", SP_ISSET(sp, SEND));
	plog(LOG_DEBUG, "RECV %d", SP_ISSET(sp, RECV));
	plog(LOG_DEBUG, "ASYMMETRIC %d", SP_ISSET(sp, ASYMMETRIC));
	plog(LOG_DEBUG, "RTCP_MUX %d", SP_ISSET(sp, RTCP_MUX));
	plog(LOG_DEBUG, "SETUP_ACTIVE %d", SP_ISSET(sp, SETUP_ACTIVE));
	plog(LOG_DEBUG, "SETUP_PASSIVE %d", SP_ISSET(sp, SETUP_PASSIVE));
	plog(LOG_DEBUG, "ICE %d", SP_ISSET(sp, ICE));
	plog(LOG_DEBUG, "STRICT_SOURCE %d", SP_ISSET(sp, STRICT_SOURCE));
	plog(LOG_DEBUG, "MEDIA_HANDOVER %d", SP_ISSET(sp, MEDIA_HANDOVER));

}

static int __retrieve_stream_params(struct redis *redis, str* callid, int stream_id,
		struct stream_params *sp, unsigned int *rtp_bridge_port, unsigned int *rtcp_bridge_port) {
	int aux_int = 0;
	char key[128], val[128];
	str aux;
	struct rtp_payload_type *pt;
	unsigned int payload_index = 0, payload_type = 0, payload_type_count = 0;
	char buf[64];

	//const char *crypto_name = NULL;
	memset(val, 0, sizeof(val));
	memset(sp, 0, sizeof(*sp));

	// get the number of payload types for the stream param
	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_PAYLOAD_COUNT_KEY));
	if (redis_get_uint(redis, "HGET", callid, key, &payload_type_count) < 0)
		goto error;
	plog(LOG_DEBUG, "Retrieve stream %s [%u]", redis_get_stream_key(STREAM_PAYLOAD_COUNT_KEY), payload_type_count);

	// get the payload types for the stream param
	for (payload_index = 0; payload_index < payload_type_count; payload_index++) {
		snprintf(key, sizeof(key), "%d:%s%d", stream_id, redis_get_stream_key(STREAM_PAYLOAD_TYPE_KEY), payload_index);
		if (redis_get_uint(redis, "HGET", callid, key, &payload_type) < 0) {
			goto error;
		}
		pt = g_slice_alloc0(sizeof(*pt));
		pt->payload_type = payload_type;
		g_queue_push_tail(&sp->rtp_payload_types, pt);
		plog(LOG_DEBUG, "Retrieve stream %s [%u]", redis_get_stream_key(STREAM_PAYLOAD_TYPE_KEY), payload_type);
	}

	// get the flags for the stream param
	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_FLAGS_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(&sp->sp_flags, aux);
	__print_flags("stream flags", sp);
	//PS_CLEAR(sp, HAS_HANDLER);
	//PS_CLEAR(sp, KERNELIZED);

	// get the rtp bridge port for the stream param
	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_RTP_BRIDGE_PORT_KEY));
	if (redis_get_uint(redis, "HGET", callid, key, rtp_bridge_port) < 0)
		goto error;
	plog(LOG_DEBUG, "Retrieve stream %s [%u]", redis_get_stream_key(STREAM_RTP_BRIDGE_PORT_KEY), *rtp_bridge_port);

	// get the rtcp bridge port for the stream param
	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_RTCP_BRIDGE_PORT_KEY));
	if (redis_get_uint(redis, "HGET", callid, key, rtcp_bridge_port) < 0)
		goto error;
	plog(LOG_DEBUG, "Retrieve stream %s [%u]", redis_get_stream_key(STREAM_RTCP_BRIDGE_PORT_KEY), *rtcp_bridge_port);

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_INDEX_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(&sp->index, aux);
	plog(LOG_DEBUG, "Retrieve stream %s [%u]", redis_get_stream_key(STREAM_INDEX_KEY), sp->index);

	// fingerprint setup for dtls
	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_FINGER_DIGEST_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(sp->fingerprint.digest, aux);

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_FINGER_NAME_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	if (aux.s) {
		sp->fingerprint.hash_func = dtls_find_hash_func(&aux);

		if (!sp->fingerprint.hash_func) {
			plog(LOG_ERR, "couldn't find dtls hash function using [%.*s]", aux.len, aux.s);
			g_free(aux.s);
			goto error;
		}

		g_free(aux.s);
	}

	// crypto setup for SDES
	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_NAME_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	if (aux.s) {
		sp->crypto.crypto_suite = crypto_find_suite(&aux);

		if (!sp->crypto.crypto_suite) {
			plog(LOG_ERR, "couldn't find crypto suite using [%.*s]", aux.len, aux.s);
			g_free(aux.s);
			goto error;
		}

		g_free(aux.s);
	}

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	if (aux.len > sizeof(sp->crypto.master_key)) {
		plog(LOG_ERR, "length is greater than master key max length\n");
		goto error;
	}
	COPY_AND_FREE(sp->crypto.master_key, aux);

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_SALT_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;

	if (aux.len > sizeof(sp->crypto.master_salt)) {
		plog(LOG_ERR, "length is greater than master salt max length\n");
		goto error;
	}
	COPY_AND_FREE(sp->crypto.master_salt, aux);

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_MKI_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(sp->crypto.mki, aux);

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_MKI_LEN_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(&sp->crypto.mki_len, aux);

	if ((sp->crypto.mki_len > 0 && !sp->crypto.mki) ||
		(sp->crypto.mki_len == 0 && sp->crypto.mki)) {
		plog(LOG_ERR, "couldn't retrieve mki\n");
		goto error;
	}

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_TYPE_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &sp->type) < 0)
		goto error;
	plog(LOG_DEBUG, "Retrieve stream %s [%.*s]", redis_get_stream_key(STREAM_TYPE_KEY), sp->type.len, sp->type.s);

	snprintf(key, sizeof(key), "%d:%s",  stream_id, redis_get_stream_key(STREAM_DIRECTION_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(&sp->direction, aux);
	plog(LOG_DEBUG, "Retrieve stream %s [%.*s]", redis_get_stream_key(STREAM_DIRECTION_KEY), sp->direction[0].len, sp->direction[0].s);
	plog(LOG_DEBUG, "Retrieve stream %s [%.*s]", redis_get_stream_key(STREAM_DIRECTION_KEY), sp->direction[1].len, sp->direction[1].s);
	//memcpy(&sp->direction, aux.s, aux.len);

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_FAMILY_KEY));
	if (redis_get_int(redis, "HGET", callid, key, &sp->desired_family) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_TRANSPORT_KEY));
	if (redis_get_int(redis, "HGET", callid, key, &aux_int) < 0)
		goto error;
	sp->protocol = &transport_protocols[aux_int];
	plog(LOG_DEBUG, "Retrieve stream %s [%s]", redis_get_stream_key(STREAM_TRANSPORT_KEY), sp->protocol->name);
	//sp->protocol->name = transport_protocols[]
	//sp->protocol->index;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_SDES_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(&sp->sdes_tag, aux);
	plog(LOG_DEBUG, "Retrieve stream %s [%u]", redis_get_stream_key(STREAM_SDES_KEY), sp->sdes_tag);

	snprintf(key, sizeof(key), "%d:%s",  stream_id, redis_get_stream_key(STREAM_RTP_ENDPOINT_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(&sp->rtp_endpoint, aux);
	smart_ntop_p(buf, &sp->rtp_endpoint.ip46, sizeof(buf));
	plog(LOG_DEBUG, "Retrieve stream %s [%s:%d]", redis_get_stream_key(STREAM_RTP_ENDPOINT_KEY), buf, sp->rtp_endpoint.port);

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_RTCP_ENDPOINT_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(&sp->rtcp_endpoint, aux);
	smart_ntop_p(buf, &sp->rtcp_endpoint.ip46, sizeof(buf));
	plog(LOG_DEBUG, "Retrieve stream %s [%s:%d]", redis_get_stream_key(STREAM_RTCP_ENDPOINT_KEY), buf, sp->rtcp_endpoint.port);

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CONSECUTIVE_PORTS_KEY));
	if (redis_get_str(redis, "HGET", callid, key, &aux) < 0)
		goto error;
	COPY_AND_FREE(&sp->consecutive_ports, aux);
	plog(LOG_DEBUG, "Retrieve stream %s [%u]", redis_get_stream_key(STREAM_CONSECUTIVE_PORTS_KEY), sp->consecutive_ports);

	return 1;
error:
	return -1;

}

static int __insert_stream_params(struct redis *redis, str* callid, int stream_id,
		struct stream_params *sp, unsigned int rtp_bridge_port, unsigned int rtcp_bridge_port) {
	char key[128];
	const char *crypto_name = __crypto_find_name(sp->crypto.crypto_suite);
        struct rtp_payload_type *pt;
	unsigned int payload_type_count = 0;

	while ((pt = g_queue_pop_head(&sp->rtp_payload_types))) {
		snprintf(key, sizeof(key), "%d:%s%d", stream_id, redis_get_stream_key(STREAM_PAYLOAD_TYPE_KEY), payload_type_count);
		if (redis_insert_uint_value_async(redis, callid, key, pt->payload_type) < 0)
			goto error;
		payload_type_count++;
	}

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_PAYLOAD_COUNT_KEY));
	if (redis_insert_uint_value_async(redis, callid, key, payload_type_count) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_FLAGS_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, &sp->sp_flags, sizeof(sp->sp_flags)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_RTP_BRIDGE_PORT_KEY));
	if (redis_insert_uint_value_async(redis, callid, key, (uint32_t)rtp_bridge_port) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_RTCP_BRIDGE_PORT_KEY));
	if (redis_insert_uint_value_async(redis, callid, key, (uint32_t)rtcp_bridge_port) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_INDEX_KEY));
	if (redis_insert_int_value_async(redis, callid, key, sp->index) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_FINGER_DIGEST_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, sp->fingerprint.digest, sizeof(sp->fingerprint.digest)) < 0)
		goto error;

	if (sp->fingerprint.hash_func) {
		snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_FINGER_NAME_KEY));
		if (redis_insert_bin_value_async(redis, callid, key, sp->fingerprint.hash_func->name, strlen(sp->fingerprint.hash_func->name)) < 0)
			goto error;
	}

	if (crypto_name) {
		snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_NAME_KEY));
		if (redis_insert_bin_value_async(redis, callid, key, crypto_name, strlen(crypto_name)) < 0)
			goto error;
	}

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, sp->crypto.master_key, sizeof(sp->crypto.master_key)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_SALT_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, sp->crypto.master_salt, sizeof(sp->crypto.master_salt)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_MKI_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, sp->crypto.mki, sp->crypto.mki_len) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CRYPTO_MKI_LEN_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->crypto.mki_len)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_TYPE_KEY));
	if (redis_insert_str_value_async(redis, callid, key, &sp->type) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s",  stream_id, redis_get_stream_key(STREAM_DIRECTION_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->direction)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_FAMILY_KEY));
	if (redis_insert_int_value_async(redis, callid, key, sp->desired_family) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_TRANSPORT_KEY));
	if (redis_insert_int_value_async(redis, callid, key, sp->protocol->index) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_SDES_KEY));
	if (redis_insert_int_value_async(redis, callid, key, sp->sdes_tag) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s",  stream_id, redis_get_stream_key(STREAM_RTP_ENDPOINT_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->rtp_endpoint)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_RTCP_ENDPOINT_KEY));
	if (redis_insert_bin_value_async(redis, callid, key, VAL_SIZE(sp->rtcp_endpoint)) < 0)
		goto error;

	snprintf(key, sizeof(key), "%d:%s", stream_id, redis_get_stream_key(STREAM_CONSECUTIVE_PORTS_KEY));
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
