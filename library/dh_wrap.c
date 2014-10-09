#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include <stdlib.h>

#include "polarssl/dh_wrap.h"


/* have to move to ssl layer later */

dh_type_t ssl_get_dh_type( key_exchange_type_t ssl_type )
{
	if( ssl_type == POLARSSL_KEY_EXCHANGE_DHE_RSA ||
            ssl_type == POLARSSL_KEY_EXCHANGE_DHE_PSK
	) return POLARSSL_DH_DHM;
	if( ssl_type == POLARSSL_KEY_EXCHANGE_ECDHE_RSA ||
            ssl_type == POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA ||
            ssl_type == POLARSSL_KEY_EXCHANGE_ECDHE_PSK ||
            ssl_type == POLARSSL_KEY_EXCHANGE_ECDH_RSA ||
            ssl_type == POLARSSL_KEY_EXCHANGE_ECDH_ECDSA ||
            ssl_type == OUR_KEY_EXCHANGE_ECDHE_TTS
	) return POLARSSL_DH_EC;
	if( ssl_type == OUR_KEY_EXCHANGE_LATTICEE_TTS ||
            ssl_type == OUR_KEY_EXCHANGE_LATTICEE_RAINBOW ||
            ssl_type == OUR_KEY_EXCHANGE_LATTICEE_RSA ||
            ssl_type == OUR_KEY_EXCHANGE_LATTICEE_ECDSA
        ) return POLARSSL_DH_LWE;

	return POLARSSL_DH_NONE;
}

const dh_info2_t * dh_get_info( dh_type_t type )
{
	if( type == POLARSSL_DH_DHM ) return &dhm_info2;
	if( type == POLARSSL_DH_EC ) return &ecdh_info2;
	if( type == POLARSSL_DH_LWE ) return &lwe_info;
	if( type == NACL_DH_CV25519 ) return &dhcv25519_info2;
	return NULL;
}





/* have to move below contents to another file later */

/* for polarssl_malloc() , polarssl_free() */
#include "polarssl/platform.h"

#define NACL_CURVE25519_C

/* Implementation that should never be optimized out by the compiler */
static void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}




#if defined(NACL_CURVE25519_C)

#include "nacl/dh_curve25519.h"


static void * dh_cv25519_alloc( void )
{
    dh_curve25519_context *ctx = polarssl_malloc( sizeof( dh_curve25519_context ) );
    if( NULL ==  ctx ) {
        return NULL;
    }
    return ctx;
}

static void dh_cv25519_free( void *_ctx ) {
    dh_curve25519_context *ctx = (dh_curve25519_context *)_ctx;
    polarssl_zeroize( ctx , sizeof( dh_curve25519_context ));
    polarssl_free( ctx );
}

static int dh_cv25519_gen_public( void *_ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    dh_curve25519_context *ctx = ( dh_curve25519_context *) _ctx;
    int ret = 0;
    if( NULL == ctx ) return (NACL_CV25519_ERR_BAD_INPUT);

    ret = f_rng( p_rng, ctx->d , crypto_scalarmult_curve25519_SCALARBYTES );
    if( 0 != ret ) return ret;

    ret = crypto_scalarmult_curve25519_base( ctx->Q , ctx->d );
    return ret;
}

static int dh_cv25519_compute_shared( void *_ctx , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    dh_curve25519_context *ctx = ( dh_curve25519_context *) _ctx;
    int ret = 0;
    if( NULL == ctx ) return (NACL_CV25519_ERR_BAD_INPUT);
    ((void)f_rng);
    ((void)p_rng);

    ret = crypto_scalarmult_curve25519( ctx->z , ctx->d , ctx->Qp );
    return ret;
}


static int dh_cv25519_set_params( void *_ctx , const void *_params )
{
    ((void)_ctx);
    ((void)_params);
    return 0;
}

static int dh_cv25519_read_public( void *_ctx, const unsigned char *buf, size_t blen )
{
    unsigned i;
    dh_curve25519_context *ctx = ( dh_curve25519_context *) _ctx;

    if( NULL == ctx ) return (NACL_CV25519_ERR_BAD_INPUT);
    if( crypto_scalarmult_curve25519_BYTES > blen ) return -1;

    for(i=0;i<crypto_scalarmult_curve25519_BYTES;i++) ctx->Qp[i] = buf[i];

    return 0;
}

static int dh_cv25519_read_params( void *ctx , int *rlen, const unsigned char *buf , size_t blen )
{
    *rlen = crypto_scalarmult_curve25519_BYTES;
    return dh_cv25519_read_public(ctx,buf,blen);
}

static size_t dh_cv25519_getsize_params( const void *ctx )
{
    ((void)ctx);
    return crypto_scalarmult_curve25519_BYTES;
}

static size_t dh_cv25519_getsize_public( const void *ctx )
{
    ((void)ctx);
    return crypto_scalarmult_curve25519_BYTES;
}

static size_t dh_cv25519_getsize_premaster( const void *ctx )
{
    ((void)ctx);
    return crypto_scalarmult_curve25519_BYTES;
}

static int dh_cv25519_write_public( size_t *olen, unsigned char *buf, size_t blen, const void *_ctx )
{
    unsigned i;
    dh_curve25519_context *ctx = ( dh_curve25519_context *) _ctx;
    if( ctx == NULL || crypto_scalarmult_curve25519_BYTES > blen )
        return( NACL_CV25519_ERR_BAD_INPUT );
    for(i=0;i<crypto_scalarmult_curve25519_BYTES;i++) buf[i] = ctx->Q[i];
    *olen = crypto_scalarmult_curve25519_BYTES;
    return 0;
}

static int dh_cv25519_write_params( size_t *olen, unsigned char *buf, size_t blen, const void *ctx )
{
    return dh_cv25519_write_public(olen,buf,blen,ctx);
}

static int dh_cv25519_write_premaster( size_t *olen, unsigned char *buf, size_t blen, const void *_ctx )
{
    unsigned i;
    dh_curve25519_context *ctx = ( dh_curve25519_context *) _ctx;
    if( ctx == NULL || crypto_scalarmult_curve25519_BYTES > blen )
        return( NACL_CV25519_ERR_BAD_INPUT );
    for(i=0;i<crypto_scalarmult_curve25519_BYTES;i++) buf[i] = ctx->z[i];
    *olen = crypto_scalarmult_curve25519_BYTES;
    return 0;
}


const dh_info2_t dhcv25519_info2 = {
    NACL_DH_CV25519,
    "CURVE25519_DH",
    dh_cv25519_alloc,
    dh_cv25519_free,
    dh_cv25519_gen_public,
    dh_cv25519_compute_shared,
    dh_cv25519_set_params,
    dh_cv25519_read_params,
    dh_cv25519_read_public,
/*
    wecdh_read_from_self_pk_ctx,
    wecdh_read_from_peer_pk_ctx,
*/
    NULL,
    NULL,
    dh_cv25519_getsize_params,
    dh_cv25519_write_params,
    dh_cv25519_getsize_public,
    dh_cv25519_write_public,
    dh_cv25519_getsize_premaster,
    dh_cv25519_write_premaster,
};


#endif /* NACL_CURVE25519_C */

