#ifndef POLARSSL_DH_H
#define POLARSSL_DH_H

/* for size_t */
#include <stdlib.h>

typedef enum {
    POLARSSL_DH_NONE=0,
    POLARSSL_DH_DHM,
    POLARSSL_DH_EC, /* Need to specify which curve to use */
    NACL_DH_CV25519,
    POLARSSL_DH_LWE,
} dh_type_t;


typedef struct {
    dh_type_t type;
    const char *name;

    void *(*ctx_alloc)( void );
    void (*ctx_free)( void *ctx );

    int (*gen_public)( void *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
    int (*compute_shared)( void *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

    int (*set_params)( void *ctx, const void *params );
    int (*read_ske_params)( void *ctx, int *rlen, const unsigned char *buf, size_t blen );
    int (*read_public)( void *ctx, const unsigned char *buf, size_t blen );

    /* A "pk_ctx" represents an interface with a certificate
     * which is initialized in pk_parse_subpubkey() in library/pkparse.c */
    int (*read_from_self_pk_ctx)( void *ctx, const void *pk_ctx );
    int (*read_from_peer_pk_ctx)( void *ctx, const void *pk_ctx );

    size_t (*getsize_ske_params)( const void *ctx );
    int (*write_ske_params)( size_t *olen, unsigned char *buf, size_t blen, const void *ctx );
    size_t (*getsize_public)( const void *ctx );
    int (*write_public)( size_t *olen, unsigned char *buf, size_t blen, const void *ctx );
    size_t (*getsize_premaster)( const void *ctx );
    int (*write_premaster)( size_t *olen, unsigned char *buf, size_t blen, const void *ctx );
} dh_info2_t;

typedef struct {
    const dh_info2_t *dh_info;
    void *dh_ctx;
} dh_context2_t;


const dh_info2_t * dh_get_info( dh_type_t type );

/* have to move to ssl layer later */
#include "polarssl/ssl_ciphersuites.h"

dh_type_t ssl_get_dh_type( key_exchange_type_t ssl_type );
int ssl_is_dh_ephemeral( key_exchange_type_t ssl_type );
int ssl_is_dh( key_exchange_type_t ssl_type );
int ssl_is_dh_pkcsign( key_exchange_type_t ssl_type );
int ssl_is_dh_psk( key_exchange_type_t ssl_type );

#endif
