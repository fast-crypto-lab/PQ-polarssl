#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include "polarssl/dh_wrap.h"



#if defined(POLARSSL_DHM_C)
#include "polarssl/dhm.h"

static void ddhm_init( void *ctx ) {
    dhm_init((dhm_context *) ctx);
    /* TODO: set P and G by mpi_... */
}

static void ddhm_free( void *ctx ) {
    dhm_free((dhm_context *) ctx);
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
    int ret =  dhm_make_public( (dhm_context *) ctx, blen, buf,
            ((dhm_context *) ctx)->P.len, /* XXX: Check olen == ctx->P.len */
            f_rng, p_rng);
    if (ret == 0) {
        *olen = ((dhm_context *) ctx)->P.len;
    }
    return ret;
}

static int ddhm_read_public( void *ctx, const unsigned char *inputbuf, size_t blen ) {
    return dhm_read_public( (dhm_context *)ctx, inputbuf, blen );
}

static int ddhm_calc_secret( void *ctx, size_t *olen, unsigned char *buf, size_t blen,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ) {
    return dhm_calc_secret( (dhm_context *)ctx, buf, olen, f_rng, p_rng);
}

const dh_info_t ddhm_info = {
    POLARSSL_DH_DHM,
    "MD2",
    ddhm_init,
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
    &ddhm_init,
    context.....
};

*/

#endif /* POLARSSL_DHM_C */




#if defined(POLARSSL_ECDH_C)
#include "polarssl/ecdh.h"

#endif /* POLARSSL_ECDH_C */

