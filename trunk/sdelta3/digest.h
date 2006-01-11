#ifndef __DIGEST_H__
#define __DIGEST_H__

/* SHA1 digest */
#define DIGEST_SIZE 20

#ifdef USE_LIBGCRYPT
#include <gcrypt.h>
#define DECLARE_DIGEST_VARS
#define GET_DIGEST(buf, sz, res) \
    gcry_md_hash_buffer(GCRY_MD_SHA1, (res), (buf), (sz))
#else /* OpenSSL */
#include <openssl/sha.h>
#define DECLARE_DIGEST_VARS \
    SHA_CTX ctx
#define GET_DIGEST(buf, sz, res) do { \
    SHA1_Init(&ctx); \
    SHA1_Update(&ctx, (buf), (sz)); \
    SHA1_Final((res), &ctx); \
} while(0)
#endif

#endif /* __DIGEST_H__ */
