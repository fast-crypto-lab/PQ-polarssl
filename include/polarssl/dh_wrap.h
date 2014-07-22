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
extern const dh_info_t ddhm_info;
#endif

#if defined(POLARSSL_ECDH_C)
extern const dh_info_t ecdh_info;
#endif

#ifdef __cplusplus
}
#endif

#endif /* POLARSSL_DH_WRAP_H */

