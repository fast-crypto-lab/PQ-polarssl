
#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_ECDH_C)

#include "polarssl/ecdh.h"

#include "polarssl/dh.h"


/*
 * BEGIN Our wrapper interfaces for ECDH key exchange
 */

int wecdh_gen_public( ecdh_context *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = 0;

    if ( ctx == NULL || ctx->grp.pbits == 0 ) return ( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    ret = ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng );

    return ret;
}

int wecdh_compute_shared( ecdh_context *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret = 0;

    if( ctx == NULL ) return ( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    ret = ecdh_compute_shared( &ctx->grp, &ctx->z, &ctx->Qp, &ctx->d, f_rng, p_rng );

    return ret;

}

static int _check_server_ecdh_params( const ecdh_context *ctx )
{
    const ecp_curve_info *curve_info;

    curve_info = ecp_curve_info_from_grp_id( ctx->grp.id );
    if( curve_info == NULL )
    {
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    }

#if defined(POLARSSL_SSL_ECP_SET_CURVES)
    {
        const ecp_group_id *gid;
        for( gid = ecp_curve_list(); *gid != POLARSSL_ECP_DP_NONE; gid++ )
            if( *gid == ctx->grp.id )
                break;
        if (*gid == POLARSSL_ECP_DP_NONE)
            return -1;
    }
#else
    if( ctx->grp.nbits < 163 ||
        ctx->grp.nbits > 521 )
        return( -1 );
#endif

    return( 0 );
}

typedef struct { int point_format; ecp_group_id group_id; } wecdh_params;

int wecdh_set_params( ecdh_context *ctx, const void *_params )
{
    int ret = 0;
    const wecdh_params *params = (const wecdh_params *) _params;

    if( ctx == NULL || params == NULL) return ( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    ctx->point_format = params->point_format;
    ret = ecp_use_known_dp( &ctx->grp, params->group_id );
    if (ret != 0) {
        return ret;
    }

    ret = _check_server_ecdh_params(ctx);
    if (ret != 0) {
        return POLARSSL_ERR_ECP_BAD_INPUT_DATA;
    }
    return ret;
}

int wecdh_read_params( ecdh_context *ctx, int *rlen, const unsigned char *buf, size_t blen )
{
    const unsigned char *p = buf;
    int ret = 0;
    const unsigned char *end = p + blen;

    ret = ecdh_read_params(ctx, &p, end);

    *rlen = p - buf;

    return ret;
}

int wecdh_read_public( ecdh_context *ctx, const unsigned char *buf, size_t blen )
{
    int ret = 0;

    ret = ecdh_read_public(ctx, buf, blen);

    return ret;
}

int wecdh_read_from_self_pk_ctx( ecdh_context *ctx, const void *_pk_ctx )
{
    const ecp_keypair *key = (const ecp_keypair *) _pk_ctx;
    int ret = -1;

    if( ( ret = ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 )
        return( ret );

    if( ( ret = ecp_copy( &ctx->Q, &key->Q ) ) != 0)
        return( ret );

    ret = mpi_copy( &ctx->d, &key->d );
    if (ret != 0) {
        return ret;
    }

    ret = _check_server_ecdh_params(ctx);
    if (ret != 0) {
        return POLARSSL_ERR_ECP_BAD_INPUT_DATA;
    }
    return ret;
}

int wecdh_read_from_peer_pk_ctx( ecdh_context *ctx, const void *_pk_ctx )
{
    const ecp_keypair *key = (const ecp_keypair *) _pk_ctx;
    int ret = -1;

    if( ( ret = ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 )
        return( ret );

    ret =( ecp_copy( &ctx->Qp, &key->Q ) );
    if (ret != 0) {
        return ret;
    }

    ret = _check_server_ecdh_params(ctx);
    if (ret != 0) {
        return POLARSSL_ERR_ECP_BAD_INPUT_DATA;
    }
    return ret;
}

size_t wecdh_getsize_public( const ecdh_context *ctx )
{
    const ecp_group grp = ctx->grp;
    const ecp_point Q = ctx->Q;
    int point_format = ctx->point_format;
    size_t point_length =  mpi_size(&grp.P);
    size_t _ = -1;

    /*
     * ecp_point_write_binary uses _ bytes to write a ECP point
     */
    if (0 == mpi_cmp_int(&Q.Z, 0)) {
        _ = 1;
    } else if (point_format == POLARSSL_ECP_PF_UNCOMPRESSED) {
        _ = 2 * point_length + 1;
    } else if (point_format == POLARSSL_ECP_PF_COMPRESSED) {
        _ = point_length + 1;
    }

    /*
     * ecp_tls_write_point uses an additional 1 byte to write length
     */
    return 1 + _;
}


size_t wecdh_getsize_params( const ecdh_context *ctx )
{
    /* In addition to the public parameter (an EC point),
     * ecp_tls_write_group uses 3 bytes */
    return 3 + wecdh_getsize_public(ctx);
}

int wecdh_write_params( size_t *olen, unsigned char *buf, size_t blen, const ecdh_context *ctx )
{
    int ret = 0;
    size_t grp_len, pt_len;

    if( ctx == NULL || blen < wecdh_getsize_params(ctx) )
        return ( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if ( (ret = ecp_tls_write_group( &ctx->grp, &grp_len, buf, blen ) ) != 0 )
        return ret;

    buf += grp_len;
    blen -= grp_len;

    ret = ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format, &pt_len, buf, blen );

    *olen = grp_len + pt_len;

    return ret;
}


int wecdh_write_public( size_t *olen, unsigned char *buf, size_t blen, const ecdh_context *ctx )
{
    int ret = 0;

    if( ctx == NULL || blen < wecdh_getsize_public(ctx) )
        return ( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    ret = ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format, olen, buf, blen );

    return ret;
}

size_t wecdh_getsize_premaster( const ecdh_context *ctx )
{
    return mpi_size(&ctx->z);
}

int wecdh_write_premaster( size_t *olen, unsigned char *buf, size_t blen, const ecdh_context *ctx )
{
    int ret = 0;

    if( ctx == NULL || blen < mpi_size(&ctx->z) )
        return ( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    *olen = ctx->grp.pbits / 8 + ( ( ctx->grp.pbits % 8 ) != 0 );
    ret = mpi_write_binary( &ctx->z, buf, *olen );

    return ret;
}



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
    wecdh_read_from_self_pk_ctx,
    wecdh_read_from_peer_pk_ctx,
    wecdh_getsize_params,
    wecdh_write_params,
    wecdh_getsize_public,
    wecdh_write_public,
    wecdh_getsize_premaster,
    wecdh_write_premaster,
};



/*
 * END Our wrapper interfaces for ECDH key exchange
 */





#endif /* defined(POLARSSL_ECDH_C) */
