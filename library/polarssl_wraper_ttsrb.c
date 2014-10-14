
#include "rainbow_tts/polarssl_wrap.h"


/* Not sure the sementic of this function */
static size_t tts_get_size( const void *ctx )
{
    ((void)ctx);
    return 8 * (TTS_PUBKEY_SIZE_BYTE + TTS_SECKEY_SIZE_BYTE);
}

static int tts_can_do( pk_type_t type )
{
    return type == OUR_PK_TTS;
}

static int __tts_verify( void *ctx, md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    unsigned char QQ_buffer[TTS_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < TTS_DIGEST_SIZE_BYTE ) ? hash_len : TTS_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;
    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    ((void)md_alg);

    // if (hash_len < TTS_DIGEST_SIZE_BYTE) {
    //     /* In fact we need another error code here */
    //     return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    // }

    if (sig_len != TTS_SIGNATURE_SIZE_BYTE) {
        return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    }

    // int verify_bin(
    //          const uint8_t * md192b ,
    //          const uint8_t * key ,
    //          const uint8_t * s320b );

    ret = tts_verify( QQ_buffer, (uint8_t *)(&((tts_context *) ctx)->pk), sig );
    if (ret != 0) {
        /* In fact we need a proper error code here */
        return -1;
    }
    return 0;
}

static int __tts_sign( void *ctx, md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    unsigned char QQ_buffer[TTS_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < TTS_DIGEST_SIZE_BYTE ) ? hash_len : TTS_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;
    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    *sig_len = TTS_SIGNATURE_SIZE_BYTE;

    return tts_sign(sig, (uint8_t *)(&((tts_context *) ctx)->sk), QQ_buffer);
}

static void *tts_alloc( void )
{
    void *ctx = polarssl_malloc( sizeof( tts_context ) );

    if( ctx != NULL )
    {
        memset( ctx, 0, sizeof( tts_context ) );
    }

    return( ctx );
}

static void tts_free( void *ctx )
{
    polarssl_zeroize( ctx, sizeof( tts_context ) );
    polarssl_free( ctx );
}

const pk_info_t tts_info = {
    OUR_PK_TTS,
    "OUR_TTS",
    tts_get_size,
    tts_can_do,
    __tts_verify,
    __tts_sign,
    NULL,
    NULL,
    tts_alloc,
    tts_free,
    NULL,
};

#if 0
static size_t rainbow_get_size( const void *ctx )
{
    return 8 * (RB_PUBKEY_SIZE_BYTE + RB_SECKEY_SIZE_BYTE);
}

static int rainbow_can_do( pk_type_t type )
{
    return type == OUR_PK_RAINBOW;
}

static int rainbow_verify( void *ctx, md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;

    if (hash_len < RB_DIGEST_SIZE_BYTE) {
        /* In fact we need another error code here */
        return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    }

    if (sig_len != RB_SIGNATURE_SIZE_BYTE) {
        return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    }

    ret = rb_verify( hash, &((rainbow_context *) ctx)->pk, sig );
    if (ret != 0) {
        /* In fact we need a proper error code here */
        return -1;
    }
    return 0;
}

static int rainbow_sign( void *ctx, md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    if (hash_len < RB_DIGEST_SIZE_BYTE) {
        /* In fact we need another error code here */
        return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    }

    *sig_len = RB_SIGNATURE_SIZE_BYTE;

    return rb_sign(sig, &((rainbow_context *) ctx)->sk, hash);
}

static void *rainbow_alloc( void )
{
    void *ctx = polarssl_malloc( sizeof( rainbow_context ) );

    if( ctx != NULL )
    {
        memset( ctx, 0, sizeof( rainbow_context ) );
    }

    return( ctx );
}

static void rainbow_free( void *ctx )
{
    polarssl_zeroize( ctx, sizeof( rainbow_context ) );
    polarssl_free( ctx );
}

const pk_info_t rainbow_info = {
    OUR_PK_RAINBOW,
    "OUR_RAINBOW",
    rainbow_get_size,
    rainbow_can_do,
    rainbow_verify,
    rainbow_sign,
    NULL,
    NULL,
    rainbow_alloc,
    rainbow_free,
    NULL,
};

#endif
