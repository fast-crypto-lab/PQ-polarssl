#ifndef POLARSSL_DH_H
#define POLARSSL_DH_H

/* for size_t */
#include <stdlib.h>

typedef enum {
    POLARSSL_DH_NONE=0,
    POLARSSL_DH_DHM,
    POLARSSL_DH_EC, /* TODO: POLARSSL_DH_EC_NISTP256, POLARSSL_DH_EC_CURVE25519, */
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

#endif
