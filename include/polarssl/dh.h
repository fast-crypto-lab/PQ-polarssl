#ifndef POLARSSL_DH_H
#define POLARSSL_DH_H

/* for size_t */
#include <stdlib.h>

typedef enum {
    POLARSSL_DH_NONE=0,
    POLARSSL_DH_DHM,
    POLARSSL_DH_EC, /* TODO: POLARSSL_DH_EC_NISTP256, POLARSSL_DH_EC_CURVE25519, */
    NACL_DH_CURVE25519,
} dh_type_t;

typedef struct {
    dh_type_t type;
    const char *name;

    void * (*ctx_alloc)( void );
    void (*ctx_free)( void *ctx );

    int (*make_params)( void *ctx, size_t *olen, unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

    int (*read_params)( void *ctx, unsigned char **buf, const unsigned char *end );

    int (*make_public)( void *ctx, size_t *olen, unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

    int (*read_public)( void *ctx, const unsigned char *inputbuf, size_t blen );

    int (*calc_secret)( void *ctx, size_t *olen, unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
} dh_info_t;

typedef struct {
    const dh_info_t *dh_info;
    void *dh_ctx;
} dh_context_t;


typedef struct {
    dh_type_t type;
    const char *name;

    void * (*ctx_alloc)( void );
    void (*ctx_free)( void *ctx );

    /* computation */
    int (*gen_public)( void *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
    int (*compute_shared)( void *ctx , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

    /*--- IO ---*/

    int (*set_params)( void *ctx , const void *params );

    /* and public */
    int (*read_ske_params)( void *ctx, int *rlen, const unsigned char *buf, size_t blen );

    int (*read_public)( void *ctx, const unsigned char *buf, size_t blen );

    /* "pk_ctx" represent an interface with a certificate */
    /* The pk_ctx is initialized in pk_parse_subpubkey() in library/pkparse.c */
    int (*read_from_self_pk_ctx)( void *ctx , const void *pk_ctx );
    int (*read_from_peer_pk_ctx)( void *ctx , const void *pk_ctx );

    /* and public */
    size_t (*getsize_ske_params)( const void *ctx );
    int (*write_ske_params)( size_t *olen, unsigned char *buf, size_t blen, const void *ctx );

    size_t (*getsize_public)( const void *ctx );
    int (*write_public)( size_t *olen , unsigned char *buf, size_t blen, const void *ctx );

    size_t (*getsize_premaster)( const void *ctx );
    int (*write_premaster)( size_t *olen, unsigned char *buf, size_t blen, const void *ctx );

} dh_info2_t;

typedef struct {
    const dh_info2_t *dh_info;
    void *dh_ctx;
} dh_context2_t;


#endif
