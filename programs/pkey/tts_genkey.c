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


extern const pk_info_t tts_info;

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
    //rsa_context rsa;
    tts_context tts;
    pk_context ctx;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    const char *pers = "tts_genkey";

    unsigned char large_buffer[256000];
    ctx.pk_info = &tts_info;
    ctx.pk_ctx = &tts;

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

    //printf( " ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE );
    printf( " ok\n  . Generating the TTS key [ %d-bit ]...", TTS_PUBKEY_SIZE_BYTE * 8 );
    fflush( stdout );

    //rsa_init( &rsa, RSA_PKCS_V15, 0 );
    
    if( ( ret = tts_genkey( &tts.pk, &tts.sk, &myrand, NULL ) ) != 0 )
    {
        printf( " failed\n  ! tts_genkey returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n  . Exporting the public  key in tts_pub.pem...." );
    fflush( stdout );

    if( ( fpub = fopen( "tts_pub.pem", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open tts_pub.pem for writing\n\n" );
        ret = 1;
        goto exit;
    }

    // if( ( ret = mpi_write_file( "N = ", &rsa.N, 16, fpub ) ) != 0 ||
    //     ( ret = mpi_write_file( "E = ", &rsa.E, 16, fpub ) ) != 0 )
    // {
    //     printf( " failed\n  ! mpi_write_file returned %d\n\n", ret );
    //     goto exit;
    // }
    ///////fwrite( &tts.pk, 1, sizeof(tts.pk), fpub );
    pk_write_pubkey_pem( &ctx, large_buffer, 256000 );
    fwrite( large_buffer, 1, 256000, fpub );

    printf( " ok\n  . Exporting the private key in tts_priv.pem..." );
    fflush( stdout );

    if( ( fpriv = fopen( "tts_priv.pem", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open tts_priv.pem for writing\n" );
        ret = 1;
        goto exit;
    }

    // if( ( ret = mpi_write_file( "N = " , &rsa.N , 16, fpriv ) ) != 0 ||
    //     ( ret = mpi_write_file( "E = " , &rsa.E , 16, fpriv ) ) != 0 ||
    //     ( ret = mpi_write_file( "D = " , &rsa.D , 16, fpriv ) ) != 0 ||
    //     ( ret = mpi_write_file( "P = " , &rsa.P , 16, fpriv ) ) != 0 ||
    //     ( ret = mpi_write_file( "Q = " , &rsa.Q , 16, fpriv ) ) != 0 ||
    //     ( ret = mpi_write_file( "DP = ", &rsa.DP, 16, fpriv ) ) != 0 ||
    //     ( ret = mpi_write_file( "DQ = ", &rsa.DQ, 16, fpriv ) ) != 0 ||
    //     ( ret = mpi_write_file( "QP = ", &rsa.QP, 16, fpriv ) ) != 0 )
    // {
    //     printf( " failed\n  ! mpi_write_file returned %d\n\n", ret );
    //     goto exit;
    // }
    pk_write_key_pem( &ctx, large_buffer, 256000 );
    fwrite( large_buffer, 1, 256000, fpriv );

/*
    printf( " ok\n  . Generating the certificate..." );

    x509write_init_raw( &cert );
    x509write_add_pubkey( &cert, &rsa );
    x509write_add_subject( &cert, "CN='localhost'" );
    x509write_add_validity( &cert, "2007-09-06 17:00:32",
                                   "2010-09-06 17:00:32" );
    x509write_create_selfsign( &cert, &rsa );
    x509write_crtfile( &cert, "cert.der", X509_OUTPUT_DER );
    x509write_crtfile( &cert, "cert.pem", X509_OUTPUT_PEM );
    x509write_free_raw( &cert );
*/
    printf( " ok\n\n" );

exit:

    if( fpub  != NULL )
        fclose( fpub );

    if( fpriv != NULL )
        fclose( fpriv );

    //rsa_free( &rsa );
    ctr_drbg_free( &ctr_drbg );
    entropy_free( &entropy );

#if defined(_WIN32)
    printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}

