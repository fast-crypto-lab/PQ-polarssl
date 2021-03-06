#ifndef POLARSSL_DH_WRAP_H
#define POLARSSL_DH_WRAP_H

#if !defined(POLARSSL_CONFIG_FILE)
#include "config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include "dh.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(POLARSSL_DHM_C)
extern const dh_info2_t dhm_info2;
#endif

#if defined(POLARSSL_ECDH_C)
extern const dh_info2_t ecdh_info2;
#endif

#if defined(LATTICE_LWEDH_C)
extern const dh_info2_t lwe_info;
#endif

#if defined(NACL_CV25519_C)

#define NACL_CV25519_ERR_BAD_INPUT       -0x3D00

extern const dh_info2_t dhcv25519_info2;
#endif

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_DH_WRAP_H */

