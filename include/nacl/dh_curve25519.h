#ifndef _DH_CURVE25519_H_
#define _DH_CURVE25519_H_


#include "crypto_scalarmult_curve25519.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct
{
    unsigned char d[crypto_scalarmult_curve25519_SCALARBYTES]; /* our secret value */
    unsigned char Q[crypto_scalarmult_curve25519_BYTES];       /* our public value */
    unsigned char Qp[crypto_scalarmult_curve25519_BYTES];      /* peer's public value */
    unsigned char z[crypto_scalarmult_curve25519_BYTES];       /* premaster secret */
}
dh_curve25519_context;



#ifdef __cplusplus
}
#endif


#endif
