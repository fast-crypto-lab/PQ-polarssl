#ifndef __HASH_SHA256_H_
#define __HASH_SHA256_H_

#if defined(__CRYPTO_EBATS__)

#include "crypto_hash_sha256.h"

static inline int _hash_sha256( unsigned char *out, const unsigned char *in, unsigned long long inlen )
{
       return crypto_hash_sha256(out,in,inlen);
}

#elif defined(__POLARSSL__)

#include "polarssl/sha256.h"

static inline int _hash_sha256( unsigned char *out, const unsigned char *in, unsigned long long inlen )
{
	sha256( in , inlen , out , 0 );
	return 0;
}

#else

#include "openssl/sha.h"

static inline int _hash_sha256( unsigned char *out, const unsigned char *in, unsigned long long inlen )
{
	SHA256(in,inlen,out);
	return 0;
}

#endif

#endif /* __HASH_SHA256_H_ */

