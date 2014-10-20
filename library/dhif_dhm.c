
#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_DHM_C)

#include "polarssl/dhm.h"

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#include <stdlib.h>
#define polarssl_printf     printf
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif


#include "polarssl/dh.h"


/* Implementation that should never be optimized out by the compiler */
//static void polarssl_zeroize( void *v, size_t n ) {
//    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
//}



/*
 * BEGIN Our wrapper interfaces for DH key exchange
 */

int wdhm_gen_public( void *_ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    dhm_context *ctx = (dhm_context *)_ctx;
    static unsigned char tmp_buffer[1536]; /* XXX: We assume that 1536 is always greater than 3*mpi_size(P) */
    int ret = 0;

    if( NULL == ctx || 0 == ctx->len ) return (POLARSSL_ERR_DHM_BAD_INPUT_DATA);

    ret = dhm_make_public(ctx, (int) ctx->len, tmp_buffer, ctx->len, f_rng, p_rng);

    return ret;
}

int wdhm_compute_shared( void *_ctx , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    dhm_context *ctx = (dhm_context *)_ctx;
    static unsigned char tmp_buffer[1536];
    size_t buffer_len = 1536;
    int ret = 0;

    ret = dhm_calc_secret(ctx, tmp_buffer, &buffer_len, f_rng, p_rng);

    return ret;
}

typedef struct { mpi P; mpi G; } wdh_params;

static int __wdhm_set_params( void *_ctx , const void *_params )
{
    dhm_context *ctx = (dhm_context *)_ctx;
    int ret = 0;
    const wdh_params *params = (const wdh_params *) _params;

    if( NULL == ctx || NULL == params ) return (POLARSSL_ERR_DHM_BAD_INPUT_DATA);

    MPI_CHK( mpi_copy( &ctx->P, &params->P ) );
    MPI_CHK( mpi_copy( &ctx->G, &params->G ) );
    ctx->len = mpi_size(&ctx->P);

cleanup:
    return ret;
}

static int wdhm_set_params( void *_ctx , const void *_params )
{
    int ret;
    struct { mpi P; mpi G; } _pa;
    mpi_init( &_pa.P );
    mpi_init( &_pa.G );
    if( NULL == _params ) {
       if( 0 != ( ret = mpi_read_string( &_pa.P , 16 , POLARSSL_DHM_RFC5114_MODP_1024_P )) ) return ret;
       if( 0 != ( ret = mpi_read_string( &_pa.G , 16 , POLARSSL_DHM_RFC5114_MODP_1024_G )) ) return ret;
       _params = (void *)&_pa;
    }
    ret = __wdhm_set_params( _ctx , _params );
    mpi_free( &_pa.P );
    mpi_free( &_pa.G );
    return ret;
}

static int _check_p_range(const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *)_ctx;
    if (ctx->len < 64 || ctx->len > 512) {
        return -1;
    }
    return 0;
}

/* and public */
int wdhm_read_params( void *_ctx , int *rlen, const unsigned char *buf , size_t blen )
{
    dhm_context *ctx = (dhm_context *)_ctx;
    const unsigned char *p = buf;
    int ret = 0;
    const unsigned char *end = p + blen;

    ret = dhm_read_params(ctx, (unsigned char **) &p, end);

    *rlen = p - buf;

    if (ret != 0) {
        return ret;
    }

    ret = _check_p_range(ctx);
    if (ret != 0) {
        return POLARSSL_ERR_DHM_BAD_INPUT_DATA;
    }
    return ret;
}

int wdhm_read_public( void *_ctx, const unsigned char *buf, size_t blen )
{
    dhm_context *ctx = (dhm_context *)_ctx;
    int ret = 0;
    size_t n;

    if (blen < 2) {
        return POLARSSL_ERR_DHM_BAD_INPUT_DATA;
    }

    n = ( buf[0] << 8 ) | buf[1];
    buf += 2;
    if (blen < 2 + n) {
        return POLARSSL_ERR_DHM_BAD_INPUT_DATA;
    }

    ret = dhm_read_public(ctx, buf, n);
    if (ret != 0) {
        return POLARSSL_ERR_DHM_BAD_INPUT_DATA;
    }

    if (blen != 2 + n) {
        return POLARSSL_ERR_DHM_BAD_INPUT_DATA;
    }

    return ret;
}

/*
 * PolarSSL does not support the DHM non-ephemeral keyexchange...

int wdhm_read_from_self_pk_ctx( dhm_context *ctx, const void *_pk_ctx ) {
    ((void)ctx);
    ((void)_pk_ctx);
    return -1;
}
int wdhm_read_from_peer_pk_ctx( dhm_context *ctx, const void *_pk_ctx ) {
    ((void)ctx);
    ((void)_pk_ctx);
    return -1;
}

 */

size_t wdhm_getsize_params( const void *_ctx )
{
    dhm_context *ctx = (dhm_context *)_ctx;
    return 3 * 2 + mpi_size(&ctx->P) + mpi_size(&ctx->G) + mpi_size(&ctx->GX);
}

int wdhm_write_params( size_t *olen, unsigned char *buf, size_t blen, const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *)_ctx;
    int ret = 0;
    unsigned char *p = buf;
    size_t n1,n2,n3;

    if( ctx == NULL || blen < wdhm_getsize_params(ctx) )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );


#define DHM_MPI_EXPORT(X,n)                     \
    MPI_CHK( mpi_write_binary( X, p + 2, n ) ); \
    *p++ = (unsigned char)( n >> 8 );           \
    *p++ = (unsigned char)( n      ); p += n;

    n1 = mpi_size( &ctx->P  );
    n2 = mpi_size( &ctx->G  );
    n3 = mpi_size( &ctx->GX );

    DHM_MPI_EXPORT( &ctx->P , n1 );
    DHM_MPI_EXPORT( &ctx->G , n2 );
    DHM_MPI_EXPORT( &ctx->GX, n3 );

    *olen = p-buf;

cleanup:
    if (ret != 0)
        return POLARSSL_ERR_DHM_MAKE_PUBLIC_FAILED + ret;

    return 0;
}

size_t wdhm_getsize_public( const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *)_ctx;
    return ctx->len + 2;
}

int wdhm_write_public( size_t *olen, unsigned char *buf, size_t blen, const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *)_ctx;
    int ret = 0;

    if( ctx == NULL || blen < ctx->len )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    MPI_CHK( mpi_write_binary(&ctx->GX, buf + 2, ctx->len) );
    buf[0] = (unsigned char)(ctx->len >> 8);
    buf[1] = (unsigned char)(ctx->len     );
    *olen = ctx->len + 2;

cleanup:
    if (ret != 0)
        return POLARSSL_ERR_DHM_MAKE_PUBLIC_FAILED + ret;

    return 0;
}

size_t wdhm_getsize_premaster( const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *)_ctx;
    return ctx->len;
}

int wdhm_write_premaster( size_t *olen, unsigned char *buf, size_t blen, const void *_ctx )
{
    const dhm_context *ctx = (const dhm_context *)_ctx;
    int ret = 0;

    if( ctx == NULL || blen < ctx->len )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

    MPI_CHK( mpi_write_binary(&ctx->K, buf, ctx->len) );
    *olen = ctx->len;

cleanup:
    if (ret != 0)
        return POLARSSL_ERR_DHM_MAKE_PUBLIC_FAILED + ret;

    return 0;
}



static void * dhm_alloc2( void ) {

    dhm_context *ctx = polarssl_malloc( sizeof( dhm_context ) );
    if( NULL ==  ctx ) {
        return NULL;
    }

    dhm_init(ctx);
    return ctx;
}

static void dhm_free2( void *ctx ) {
    dhm_free((dhm_context *) ctx);
    polarssl_free( ctx );
}


const dh_info2_t dhm_info2 = {
    POLARSSL_DH_DHM,
    "DHMif2",
    dhm_alloc2,
    dhm_free2,
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




/*
 * END Our wrapper interfaces for DH key exchange
 */

#endif /* defined(POLARSSL_DHM_C) */
