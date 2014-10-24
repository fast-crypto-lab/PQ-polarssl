
#include "polarssl/platform.h"

#include "rainbow_tts/polarssl_wrap.h"

static void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

#if defined(__TTS__)

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
    //for hash function with shorter output
    unsigned char QQ_buffer[TTS_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < TTS_DIGEST_SIZE_BYTE ) ? hash_len : TTS_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;
    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    ((void)md_alg);

    printf("\n*** INSIDE pk_info->verify_func() function ***\n"
           " The hash_len = %zu 'hash' gets truncated or padded"
           " ---> n_bytes = %zu 'QQ_buffer'\n", hash_len, n_bytes);

    if (sig_len != TTS_SIGNATURE_SIZE_BYTE) {
        return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    }

    ret = tts_verify( QQ_buffer, (const uint8_t *)(&((tts_context *) ctx)->pk), sig );
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

    ((void) md_alg);
    ((void) f_rng);
    ((void) p_rng);

    printf("\n*** INSIDE pk_info->sign_func() function ***\n"
           " The hash_len = %zu 'hash' gets truncated or padded"
           " ---> n_bytes = %zu 'QQ_buffer'\n", hash_len, n_bytes);

    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    *sig_len = TTS_SIGNATURE_SIZE_BYTE;

    return tts_sign(sig, (const uint8_t *)(&((tts_context *) ctx)->sk), QQ_buffer);
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

#endif /* __TTS__ */

#if defined(__RAINBOW__)

static size_t rainbow_get_size( const void *ctx )
{
    ((void) ctx);
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
    unsigned char QQ_buffer[RB_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < RB_DIGEST_SIZE_BYTE ) ? hash_len : RB_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;

    ((void) md_alg);

    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    printf("\n*** INSIDE pk_info->verify_func() function ***\n"
           " The hash_len = %zu 'hash' gets truncated or padded"
           " ---> n_bytes = %zu 'QQ_buffer'\n", hash_len, n_bytes);

    //if (hash_len < RB_DIGEST_SIZE_BYTE) {
    //    /* In fact we need another error code here */
    //    return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    //}

    if (sig_len != RB_SIGNATURE_SIZE_BYTE) {
        return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    }

    ret = rb_verify( QQ_buffer, (const uint8_t *)&((rainbow_context *) ctx)->pk, sig );
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
    unsigned char QQ_buffer[RB_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < RB_DIGEST_SIZE_BYTE ) ? hash_len : RB_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;

    ((void) md_alg);
    ((void) f_rng);
    ((void) p_rng);

    printf("\n*** INSIDE pk_info->sign_func() function ***\n"
           " The hash_len = %zu 'hash' gets truncated or padded"
           " ---> n_bytes = %zu 'QQ_buffer'\n", hash_len, n_bytes);

    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    *sig_len = RB_SIGNATURE_SIZE_BYTE;

    return rb_sign(sig, (const uint8_t *) &((rainbow_context *) ctx)->sk, QQ_buffer);
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

#endif /* __RAINBOW__ */

#if defined(__TTS_2__)

/* Not sure the sementic of this function */
static size_t tts2_get_size( const void *ctx )
{
    ((void)ctx);
    return 8 * (TTS2_PUBKEY_SIZE_BYTE + TTS2_SECKEY_SIZE_BYTE);
}

static int tts2_can_do( pk_type_t type )
{
    return type == OUR_PK_TTS2;
}

static int __tts2_verify( void *ctx, md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    unsigned char QQ_buffer[TTS2_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < TTS2_DIGEST_SIZE_BYTE ) ? hash_len : TTS2_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;

    ((void) md_alg);

    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    printf("\n*** INSIDE pk_info->verify_func() function ***\n"
           " The hash_len = %zu 'hash' gets truncated or padded"
           " ---> n_bytes = %zu 'QQ_buffer'\n", hash_len, n_bytes);

    ((void)md_alg);

    if (sig_len != TTS2_SIGNATURE_SIZE_BYTE) {
        return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    }


    ret = tts2_verify( QQ_buffer, (const uint8_t *)(&((tts2_context *) ctx)->pk), sig );
    if (ret != 0) {
        /* In fact we need a proper error code here */
        return -1;
    }
    return 0;
}

static int __tts2_sign( void *ctx, md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    unsigned char QQ_buffer[TTS2_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < TTS2_DIGEST_SIZE_BYTE ) ? hash_len : TTS2_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;

    ((void) md_alg);
    ((void) f_rng);
    ((void) p_rng);

    printf("\n*** INSIDE pk_info->sign_func() function ***\n"
           " The hash_len = %zu 'hash' gets truncated or padded"
           " ---> n_bytes = %zu 'QQ_buffer'\n", hash_len, n_bytes);

    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    *sig_len = TTS2_SIGNATURE_SIZE_BYTE;

    return tts2_sign(sig, (uint8_t *)(&((tts2_context *) ctx)->sk), QQ_buffer);
}

static void *tts2_alloc( void )
{
    void *ctx = polarssl_malloc( sizeof( tts2_context ) );

    if( ctx != NULL )
    {
        memset( ctx, 0, sizeof( tts2_context ) );
    }

    return( ctx );
}

static void tts2_free( void *ctx )
{
    polarssl_zeroize( ctx, sizeof( tts2_context ) );
    polarssl_free( ctx );
}


const pk_info_t tts2_info = {
    OUR_PK_TTS2,
    "OUR_TTS2",
    tts2_get_size,
    tts2_can_do,
    __tts2_verify,
    __tts2_sign,
    NULL,
    NULL,
    tts2_alloc,
    tts2_free,
    NULL,
};

#endif /* __TTS_2__ */

#if defined(__RAINBOW_2__)

static size_t rainbow2_get_size( const void *ctx )
{
    ((void) ctx);
    return 8 * (RB2_PUBKEY_SIZE_BYTE + RB2_SECKEY_SIZE_BYTE);
}

static int rainbow2_can_do( pk_type_t type )
{
    return type == OUR_PK_RAINBOW2;
}

static int rainbow2_verify( void *ctx, md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len )
{
    int ret;
    unsigned char QQ_buffer[RB2_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < RB2_DIGEST_SIZE_BYTE ) ? hash_len : RB2_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;

    ((void) md_alg);

    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    printf("\n*** INSIDE pk_info->verify_func() function ***\n"
           " The hash_len = %zu 'hash' gets truncated or padded"
           " ---> n_bytes = %zu 'QQ_buffer'\n", hash_len, n_bytes);

    if (sig_len != RB2_SIGNATURE_SIZE_BYTE) {
        return POLARSSL_ERR_PK_SIG_LEN_MISMATCH;
    }

    ret = rb2_verify( QQ_buffer, (const uint8_t *)&((rainbow2_context *) ctx)->pk, sig );
    if (ret != 0) {
        /* In fact we need a proper error code here */
        return -1;
    }
    return 0;
}

static int rainbow2_sign( void *ctx, md_type_t md_alg,
                   const unsigned char *hash, size_t hash_len,
                   unsigned char *sig, size_t *sig_len,
                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    unsigned char QQ_buffer[RB2_DIGEST_SIZE_BYTE] = { 0 };
    unsigned int n_bytes = ( hash_len < RB2_DIGEST_SIZE_BYTE ) ? hash_len : RB2_DIGEST_SIZE_BYTE;
    unsigned int _i = 0;

    ((void) md_alg);
    ((void) f_rng);
    ((void) p_rng);

    printf("\n*** INSIDE pk_info->sign_func() function ***\n"
           " The hash_len = %zu 'hash' gets truncated or padded"
           " ---> n_bytes = %zu 'QQ_buffer'\n", hash_len, n_bytes);

    for (_i = 0; _i < n_bytes; ++_i) {
        QQ_buffer[_i] = hash[_i];
    }

    *sig_len = RB2_SIGNATURE_SIZE_BYTE;

    return rb2_sign(sig, (const uint8_t *) &((rainbow2_context *) ctx)->sk, QQ_buffer);
}

static void *rainbow2_alloc( void )
{
    void *ctx = polarssl_malloc( sizeof( rainbow2_context ) );

    if( ctx != NULL )
    {
        memset( ctx, 0, sizeof( rainbow2_context ) );
    }

    return( ctx );
}

static void rainbow2_free( void *ctx )
{
    polarssl_zeroize( ctx, sizeof( rainbow2_context ) );
    polarssl_free( ctx );
}


const pk_info_t rainbow2_info = {
    OUR_PK_RAINBOW2,
    "OUR_RAINBOW2",
    rainbow2_get_size,
    rainbow2_can_do,
    rainbow2_verify,
    rainbow2_sign,
    NULL,
    NULL,
    rainbow2_alloc,
    rainbow2_free,
    NULL,
};
#endif /* __RAINBOW_2__ */

