#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif


#include <stdlib.h>


#include "polarssl/dh_wrap.h"

/* for polarssl_malloc() , polarssl_free() */
#include "polarssl/platform.h"

/* Implementation that should never be optimized out by the compiler */
static void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}


#if defined(POLARSSL_DHM_C)

#include "polarssl/bignum.h"
#include "polarssl/dhm.h"

static void * ddhm_alloc( void ) {

    dhm_context *ctx = polarssl_malloc( sizeof( dhm_context ) );
    if( NULL ==  ctx ) {
        return NULL;
    }

    dhm_init(ctx);

    if( mpi_read_string( & ctx->P, 16, POLARSSL_DHM_RFC5114_MODP_1024_P) ||
        mpi_read_string( & ctx->G, 16, POLARSSL_DHM_RFC5114_MODP_1024_G) ) {
        dhm_free(ctx);
        ctx = NULL;
    }
    ctx->len = mpi_size( & ctx->P );

    return ctx;
}

static void ddhm_free( void *ctx ) {
    dhm_free((dhm_context *) ctx);
    polarssl_free( ctx );
}


static int ddhm_make_params( void *ctx, size_t *olen, unsigned char *buf, size_t blen,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
    return dhm_make_params( (dhm_context *)ctx, blen, buf, olen, f_rng, p_rng );
}

static int ddhm_read_params( void *ctx, unsigned char **buf, const unsigned char *end ) {
    return dhm_read_params( (dhm_context *) ctx, buf, end);
}

static int ddhm_make_public( void *ctx, size_t *olen, unsigned char *buf, size_t blen,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
    size_t plen = mpi_size( & ((dhm_context *) ctx)->P );
    int ret =  dhm_make_public( (dhm_context *) ctx, blen, buf,
            plen, /* XXX: Check olen == ctx->P.len */
            f_rng, p_rng);
    if (ret == 0) {
        *olen = plen;
    }
    return ret;
}

static int ddhm_read_public( void *ctx, const unsigned char *inputbuf, size_t blen ) {
    return dhm_read_public( (dhm_context *)ctx, inputbuf, blen );
}

static int ddhm_calc_secret( void *ctx, size_t *olen, unsigned char *buf, size_t blen,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
    *olen = blen;
    return dhm_calc_secret( (dhm_context *)ctx, buf, olen, f_rng, p_rng);
}

const dh_info_t ddhm_info = {
    POLARSSL_DH_DHM,
    "DDHM",
    ddhm_alloc,
    ddhm_free,
    ddhm_make_params,
    ddhm_read_params,
    ddhm_make_public,
    ddhm_read_public,
    ddhm_calc_secret,
};

/*
 * The user (SSL side) need to handle these...

const dh_context_t ddhm_ctx = {
    &ddhm_info,
    context.....
};

*/

#endif /* POLARSSL_DHM_C */





#if defined(POLARSSL_ECDH_C)

#include "polarssl/platform.h"
#include "polarssl/ecdh.h"

/* TODO: Use ecp_use_known_dp() to select a particular curve for each ECDH wrapper */
static void *m_ecdh_alloc( void ) {
    ecdh_context *ctx = polarssl_malloc( sizeof( ecdh_context ) );
    if ( ctx == NULL ) {
        return NULL;
    } else {
        ecdh_init(ctx);
        return ctx;
    }
}

static void m_ecdh_free( void *ctx ) {
    ecdh_free( (ecdh_context *) ctx );
    polarssl_free( ctx );
}

static int m_ecdh_make_params( void *ctx, size_t *olen, unsigned char *buf,
        size_t blen, int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng ) {

    return ecdh_make_params(
            (ecdh_context *)ctx, olen, buf, blen, f_rng, p_rng );
}

static int m_ecdh_read_params( void *ctx, unsigned char **buf,
        const unsigned char *end ) {

    return ecdh_read_params( (ecdh_context *)ctx, (const unsigned char **) buf, end ); /* Type casting to supress compiler warning */
}

static int m_ecdh_make_public( void *ctx, size_t *olen, unsigned char *buf,
        size_t blen, int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng ) {

    return ecdh_make_public(
            (ecdh_context *)ctx, olen, buf, blen, f_rng, p_rng );
}

static int m_ecdh_read_public( void *ctx, const unsigned char *inputbuf,
        size_t blen ) {

    return ecdh_read_public( (ecdh_context *)ctx, inputbuf, blen );
}

static int m_ecdh_calc_secret( void *ctx, size_t *olen, unsigned char *buf,
        size_t blen, int (*f_rng)(void *, unsigned char *, size_t),
        void *p_rng ) {

    return ecdh_calc_secret(
            (ecdh_context *)ctx, olen, buf, blen, f_rng, p_rng );
}

const dh_info_t m_ecdh_info = {
    POLARSSL_DH_EC,
    "M_ECDH",
    m_ecdh_alloc,
    m_ecdh_free,
    m_ecdh_make_params,
    m_ecdh_read_params,
    m_ecdh_make_public,
    m_ecdh_read_public,
    m_ecdh_calc_secret,
};

#endif /* POLARSSL_ECDH_C */




#if defined(POLARSSL_DHM_C)

#include "polarssl/dhm.h"

static void * dhm_alloc2( void ) {

    dhm_context *ctx = polarssl_malloc( sizeof( dhm_context ) );
    if( NULL ==  ctx ) {
        return NULL;
    }

    dhm_init(ctx);
    return ctx;
}

const dh_info2_t dhm_info2 = {
    POLARSSL_DH_DHM,
    "DHMif2",
    dhm_alloc2,
    ddhm_free,
    wdhm_gen_public,
    wdhm_compute_shared,
    wdhm_set_params,
    wdhm_read_params,
    wdhm_read_public,
    NULL,
    NULL,
    wdhm_getsize_params,
    wdhm_write_params,
    wdhm_getsize_public,
    wdhm_write_public,
    wdhm_getsize_premaster,
    wdhm_write_premaster,
};


#endif /* POLARSSL_DHM_C */



#if defined(POLARSSL_ECDH_C)

#include "polarssl/ecdh.h"

/* TODO: modified*/
const dh_info2_t ecdh_info2 = {
    POLARSSL_DH_EC,
    "M_ECDH2",
    m_ecdh_alloc,
    m_ecdh_free,
    wecdh_gen_public,
    wecdh_compute_shared,
    wecdh_set_params,
    wecdh_read_params,
    wecdh_read_public,
/*
    wecdh_read_from_self_pk_ctx,
    wecdh_read_from_peer_pk_ctx,
*/
    NULL,
    NULL,
    wecdh_getsize_params,
    wecdh_write_params,
    wecdh_getsize_public,
    wecdh_write_public,
    wecdh_getsize_premaster,
    wecdh_write_premaster,
};


#endif /* POLARSSL_ECDH_C */



#define NACL_CURVE25519_C

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
    if( NULL == ctx ) return (POLARSSL_ERR_DHM_BAD_INPUT_DATA);

    ret = f_rng( p_rng, ctx->d , crypto_scalarmult_curve25519_SCALARBYTES );
    if( 0 != ret ) return ret;

    ret = crypto_scalarmult_curve25519_base( ctx->Q , ctx->d );
    return ret;
}

static int dh_cv25519_compute_shared( void *_ctx , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    dh_curve25519_context *ctx = ( dh_curve25519_context *) _ctx;
    int ret = 0;
    if( NULL == ctx ) return (POLARSSL_ERR_DHM_BAD_INPUT_DATA);

    ret = crypto_scalarmult_curve25519( ctx->z , ctx->d , ctx->Qp );
    return ret;
}


static int dh_cv25519_set_params( void *_ctx , const void *_params )
{
    return 0;
}

static int dh_cv25519_read_public( void *_ctx, const unsigned char *buf, size_t blen )
{
    unsigned i;
    dh_curve25519_context *ctx = ( dh_curve25519_context *) _ctx;

    if( NULL == ctx ) return (POLARSSL_ERR_DHM_BAD_INPUT_DATA);
    if( crypto_scalarmult_curve25519_BYTES > blen ) return -1;

    for(i=0;i<crypto_scalarmult_curve25519_BYTES;i++) ctx->Qp[i] = buf[i];
    return 0;
}

static int dh_cv25519_read_params( void *ctx , const unsigned char *buf , size_t blen )
{
    return dh_cv25519_read_public(ctx,buf,blen);
}

static size_t dh_cv25519_getsize_params( const void *ctx )
{
    return crypto_scalarmult_curve25519_BYTES;
}

static size_t dh_cv25519_getsize_public( const void *ctx )
{
    return crypto_scalarmult_curve25519_BYTES;
}

static size_t dh_cv25519_getsize_premaster( const void *ctx )
{
    return crypto_scalarmult_curve25519_BYTES;
}

static int dh_cv25519_write_public( size_t *olen, unsigned char *buf, size_t blen, const void *_ctx )
{
    unsigned i;
    dh_curve25519_context *ctx = ( dh_curve25519_context *) _ctx;
    if( ctx == NULL || crypto_scalarmult_curve25519_BYTES > blen )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );
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
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );
    for(i=0;i<crypto_scalarmult_curve25519_BYTES;i++) buf[i] = ctx->z[i];
    *olen = crypto_scalarmult_curve25519_BYTES;
    return 0;
}


const dh_info2_t dhcv25519_info2 = {
    NACL_DH_CURVE25519,
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

