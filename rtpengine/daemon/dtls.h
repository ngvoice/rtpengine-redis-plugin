#ifndef _DTLS_H_
#define _DTLS_H_



#include <time.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "compat.h"
#include "str.h"
#include "obj.h"




#define DTLS_MAX_DIGEST_LEN 64




struct packet_stream;
struct sockaddr_in6;
struct poller;



struct dtls_hash_func {
	const char *name;
	unsigned int num_bytes;
	unsigned int (*__func)(unsigned char *, X509 *);
};

struct dtls_fingerprint {
	unsigned char digest[DTLS_MAX_DIGEST_LEN];
	const struct dtls_hash_func *hash_func;
};

struct dtls_cert {
	struct obj obj;
	struct dtls_fingerprint fingerprint;
	EVP_PKEY *pkey;
	X509 *x509;
	time_t expires;
};

struct dtls_connection {
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	BIO *r_bio, *w_bio;
	int init:1,
	    active:1,
	    connected:1;
};




int dtls_init(void);
void dtls_timer(struct poller *);

int dtls_verify_cert(struct packet_stream *ps);
const struct dtls_hash_func *dtls_find_hash_func(const str *);
struct dtls_cert *dtls_cert(void);

int dtls_connection_init(struct packet_stream *, int active, struct dtls_cert *cert);
int dtls(struct packet_stream *, const str *s, struct sockaddr_in6 *sin);
void dtls_connection_cleanup(struct dtls_connection *);




INLINE void __dtls_hash(const struct dtls_hash_func *hash_func, X509 *cert, unsigned char *out,
		unsigned int bufsize)
{
	unsigned int n;

	assert(bufsize >= hash_func->num_bytes);
	n = hash_func->__func(out, cert);
	assert(n == hash_func->num_bytes);
}
#define dtls_hash(hash_func, cert, outbuf) __dtls_hash(hash_func, cert, outbuf, sizeof(outbuf))

INLINE void dtls_fingerprint_hash(struct dtls_fingerprint *fp, X509 *cert) {
	__dtls_hash(fp->hash_func, cert, fp->digest, sizeof(fp->digest));
}

INLINE int is_dtls(const str *s) {
	const unsigned char *b = (const void *) s->s;

	if (s->len < 1)
		return 0;
	/* RFC 5764, 5.1.2 */
	if (b[0] >= 20 && b[0] <= 63)
		return 1;

	return 0;
}




#endif
