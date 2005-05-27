#ifndef __DIGEST_H__
#define __DIGEST_H__

/* SHA1 digest */
#define DIGEST_SIZE 20

#if defined(USE_GNUTLS10) || defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
#ifdef USE_GNUTLS10
typedef gnutls_datum gnutls_datum_t;
#endif
#define DECLARE_DIGEST_VARS \
    gnutls_datum_t datum; \
    size_t digest_buf_size
#define GET_DIGEST(buf, sz, res) do { \
    datum.data = (buf); \
    datum.size = (sz); \
    digest_buf_size = DIGEST_SIZE; \
    gnutls_fingerprint(GNUTLS_DIG_SHA, &datum, (res), &digest_buf_size); \
} while(0)
#else /* OpenSSL or libmd */
#ifdef USE_LIBMD
#include <sha.h>
#else
#include <openssl/sha.h>
#endif
#define DECLARE_DIGEST_VARS \
    SHA_CTX ctx
#define GET_DIGEST(buf, sz, res) do { \
    SHA1_Init(&ctx); \
    SHA1_Update(&ctx, (buf), (sz)); \
    SHA1_Final((res), &ctx); \
} while(0)
#endif

#endif /* __DIGEST_H__ */
