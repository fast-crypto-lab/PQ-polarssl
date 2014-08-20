/*
 *  Elliptic curve Diffie-Hellman
 *
 *  Copyright (C) 2006-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 * RFC 4492
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_ECDH_C)

#include "polarssl/ecdh.h"

/*
 * Generate public key: simple wrapper around ecp_gen_keypair
 */
int ecdh_gen_public( ecp_group *grp, mpi *d, ecp_point *Q,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng )
{
    return ecp_gen_keypair( grp, d, Q, f_rng, p_rng );
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int ecdh_compute_shared( ecp_group *grp, mpi *z,
                         const ecp_point *Q, const mpi *d,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng )
{
    int ret;
    ecp_point P;

    ecp_point_init( &P );

    /*
     * Make sure Q is a valid pubkey before using it
     */
    MPI_CHK( ecp_check_pubkey( grp, Q ) );

    MPI_CHK( ecp_mul( grp, &P, d, Q, f_rng, p_rng ) );

    if( ecp_is_zero( &P ) )
    {
        ret = POLARSSL_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MPI_CHK( mpi_copy( z, &P.X ) );

cleanup:
    ecp_point_free( &P );

    return( ret );
}

/*
 * Initialize context
 */
void ecdh_init( ecdh_context *ctx )
{
    memset( ctx, 0, sizeof( ecdh_context ) );
}

/*
 * Free context
 */
void ecdh_free( ecdh_context *ctx )
{
    if( ctx == NULL )
        return;

    ecp_group_free( &ctx->grp );
    ecp_point_free( &ctx->Q   );
    ecp_point_free( &ctx->Qp  );
    ecp_point_free( &ctx->Vi  );
    ecp_point_free( &ctx->Vf  );
    mpi_free( &ctx->d  );
    mpi_free( &ctx->z  );
    mpi_free( &ctx->_d );
}

/*
 * Setup and write the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int ecdh_make_params( ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret;
    size_t grp_len, pt_len;

    if( ctx == NULL || ctx->grp.pbits == 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) )
                != 0 )
        return( ret );

    if( ( ret = ecp_tls_write_group( &ctx->grp, &grp_len, buf, blen ) )
                != 0 )
        return( ret );

    buf += grp_len;
    blen -= grp_len;

    if( ( ret = ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format,
                                     &pt_len, buf, blen ) ) != 0 )
        return( ret );

    *olen = grp_len + pt_len;
    return( 0 );
}

/*
 * Read the ServerKeyExhange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int ecdh_read_params( ecdh_context *ctx,
                      const unsigned char **buf, const unsigned char *end )
{
    int ret;

    if( ( ret = ecp_tls_read_group( &ctx->grp, buf, end - *buf ) ) != 0 )
        return( ret );

    if( ( ret = ecp_tls_read_point( &ctx->grp, &ctx->Qp, buf, end - *buf ) )
                != 0 )
        return( ret );

    return( 0 );
}

/*
 * Get parameters from a keypair
 */
int ecdh_get_params( ecdh_context *ctx, const ecp_keypair *key,
                     ecdh_side side )
{
    int ret;

    if( ( ret = ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 )
        return( ret );

    /* If it's not our key, just import the public part as Qp */
    if( side == POLARSSL_ECDH_THEIRS )
        return( ecp_copy( &ctx->Qp, &key->Q ) );

    /* Our key: import public (as Q) and private parts */
    if( side != POLARSSL_ECDH_OURS )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecp_copy( &ctx->Q, &key->Q ) ) != 0 ||
        ( ret = mpi_copy( &ctx->d, &key->d ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Setup and export the client public value
 */
int ecdh_make_public( ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret;

    if( ctx == NULL || ctx->grp.pbits == 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) )
                != 0 )
        return( ret );

    return ecp_tls_write_point( &ctx->grp, &ctx->Q, ctx->point_format,
                                olen, buf, blen );
}

/*
 * Parse and import the client's public value
 */
int ecdh_read_public( ecdh_context *ctx,
                      const unsigned char *buf, size_t blen )
{
    int ret;
    const unsigned char *p = buf;

    if( ctx == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecp_tls_read_point( &ctx->grp, &ctx->Qp, &p, blen ) ) != 0 )
        return( ret );

    if( (size_t)( p - buf ) != blen )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    return( 0 );
}

/*
 * Derive and export the shared secret
 */
int ecdh_calc_secret( ecdh_context *ctx, size_t *olen,
                      unsigned char *buf, size_t blen,
                      int (*f_rng)(void *, unsigned char *, size_t),
                      void *p_rng )
{
    int ret;

    if( ctx == NULL )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    if( ( ret = ecdh_compute_shared( &ctx->grp, &ctx->z, &ctx->Qp, &ctx->d,
                                     f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    if( mpi_size( &ctx->z ) > blen )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    *olen = ctx->grp.pbits / 8 + ( ( ctx->grp.pbits % 8 ) != 0 );
    return mpi_write_binary( &ctx->z, buf, *olen );
}


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

int wecdh_write_public( size_t *olen, unsigned char *buf, size_t blen, const ecdh_context *ctx )
{
    int ret = 0;

    if( ctx == NULL || blen < sizeof(ctx->Q) )
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

/*
 * END Our wrapper interfaces for ECDH key exchange
 */



#if defined(POLARSSL_SELF_TEST)

/*
 * Checkup routine
 */
int ecdh_self_test( int verbose )
{
    ((void) verbose );
    return( 0 );
}

#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_ECDH_C */
