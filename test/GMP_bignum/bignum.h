#ifndef POLARSSL_BIGNUM_H
#define POLARSSL_BIGNUM_H

#include <gmp.h>
#include <stdlib.h>

typedef mpz_t mpi;

int mpi_read_string( mpi *X, int radix, const char *s );
size_t mpi_size( mpi *X );
void mpi_init( mpi *X );
int mpi_lset( mpi *X, int  z );
int mpi_inv_mod( mpi *X, mpi *A, mpi *N );
int mpi_mul_mpi( mpi *X, mpi *A, mpi *B );
int mpi_mod_mpi( mpi *R, mpi *A, mpi *B );
int mpi_sub_int( mpi *X, mpi *A, int b );
int mpi_div_int( mpi *Q, mpi *R, mpi *A, int	 b );
int mpi_sub_mpi( mpi *X, mpi *A, mpi *B );
int mpi_div_mpi( mpi *Q, mpi *R, mpi *A, mpi *B );
int mpi_exp_mod( mpi *X, mpi *A, mpi *E, mpi *N, mpi *_RR );
int mpi_copy( mpi *X, mpi *Y );
int mpi_add_mpi( mpi *X, mpi *A, mpi *B );
int mpi_write_binary( mpi *X, unsigned char *buf, size_t buflen );
int mpi_read_binary( mpi *X, unsigned char *buf, size_t buflen );
int mpi_cmp_int( mpi *X, int z );

int mpi_mul_int( mpi *X, mpi *A, int	 b );


#endif




