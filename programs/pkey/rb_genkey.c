#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#include <stdlib.h>
#include <stdio.h>

#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
//#include "polarssl/bignum.h"
#include "polarssl/x509.h"
//#include "polarssl/rsa.h"
#include "rainbow_tts/rainbow.h"


extern const pk_info_t rainbow_info;

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;

    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

int main( int argc, char *argv[] )
{
    int ret;
    rainbow_context rb;
    pk_context ctx;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rb_genkey";

    unsigned char large_buffer[256000];
    ctx.pk_info = &rainbow_info;
    ctx.pk_ctx = &rb;

    ((void) argc);
    ((void) argv);

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    entropy_init( &entropy );
    if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
        goto exit;
    }

    printf( " ok\n  . Generating the TTS key [ %d-bit ]...", TTS_PUBKEY_SIZE_BYTE * 8 );
    fflush( stdout );


    if( ( ret = rb_genkey( (uint8_t *) &rb.pk, (uint8_t *) &rb.sk, &myrand, NULL ) ) != 0 )
    {
        printf( " failed\n  ! rb_genkey returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n  . Exporting the public  key in ./self-signed/rb-pub.pem...." );
    fflush( stdout );

    if( ( fpub = fopen( "./self-signed/rb-pub.pem", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open ./self-signed/rb-pub.pem for writing\n\n" );
        ret = 1;
        goto exit;
    }
    pk_write_pubkey_pem( &ctx, large_buffer, 256000 );
    fwrite( large_buffer, 1, 256000, fpub );

    printf( " ok\n  . Exporting the private key in ./self-signed/rb-prv.pem..." );
    fflush( stdout );

    if( ( fpriv = fopen( "./self-signed/rb-prv.pem", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open ./self-signed/rb-prv.pem for writing\n" );
        ret = 1;
        goto exit;
    }

    pk_write_key_pem( &ctx, large_buffer, 256000 );
    fwrite( large_buffer, 1, 256000, fpriv );
    printf( " ok\n\n" );

exit:

    if( fpub  != NULL )
        fclose( fpub );

    if( fpriv != NULL )
        fclose( fpriv );

    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}

