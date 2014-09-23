#include "bignum.h"



int mpi_read_string( mpi *X, int radix, const char *s ){
	return mpz_set_str (*X, s, radix);
}

size_t mpi_size( mpi *X ){
	return (mpz_sizeinbase (*X, 2) + 7) / 8;
}
void mpi_init( mpi *X ){
	mpz_init(*X);
}
int mpi_lset( mpi *X, int  z ){
	mpz_set_ui(*X, z);
	return  0;
}
int mpi_inv_mod( mpi *X, mpi *A, mpi *N ){
	return mpz_invert(*X, *A, *N);
}
int mpi_mul_mpi( mpi *X, mpi *A, mpi *B ){
	mpz_mul(*X, *A, *B);
	return 0;
}
int mpi_mul_int( mpi *X, mpi *A, int	 b ){
	mpz_mul_si(*X, *A, b);
	return 0;
}
int mpi_add_mpi( mpi *X, mpi *A, mpi *B ){
	mpz_add(*X, *A, *B);
	return 0;
}
int mpi_sub_mpi( mpi *X, mpi *A, mpi *B ){
	mpz_sub(*X, *A, *B);
	return 0;
}
int mpi_sub_int( mpi *X, mpi *A, int  b ){
	mpz_sub_ui(*X, *A, b);
	return 0;
}

int mpi_mod_mpi( mpi *R, mpi *A, mpi *B ){
	 mpz_mod(*R, *A, *B);
	return 0;
}

int mpi_div_mpi( mpi *Q, mpi *R, mpi *A, mpi *B ){
	if(R == NULL)
		mpz_tdiv_q (*Q, *A, *B);
	else
		mpz_tdiv_r (*R, *A, *B);
	return 0;
}
int mpi_div_int( mpi *Q, mpi *R, mpi *A, int	 b ){
	if(R == NULL)
		mpz_tdiv_q_ui (*Q, *A, b);
	else
		mpz_tdiv_r_ui (*R, *A, b);
	return 0;
}

int mpi_exp_mod( mpi *X, mpi *A, mpi *E, mpi *N, mpi *_RR ){
	mpz_powm(*X, *A, *E, *N);
	return 0;
}
int mpi_copy( mpi *X, mpi *Y ){
	mpz_set(*X, *Y);
	return 0;
}

int mpi_write_binary( mpi *X, unsigned char *buf, size_t buflen ){
	memset (buf, 0 ,buflen);
	mpz_export (buf, NULL, 1, 1, 0, 0,*X);
	return 0;
}
int mpi_read_binary( mpi *X, unsigned char *buf, size_t buflen ){
	mpz_import (*X, buflen , 1, 1, 0, 0, buf);
	return 0;
}
int mpi_cmp_int( mpi *X, int z ){
	return mpz_cmp_si(*X, z);
}
int mpi_cmp_abs( const mpi *X, const mpi *Y ){
	return mpz_cmpabs(*X, *Y);
}
int mpi_cmp_mpi( const mpi *X, const mpi *Y ){
	return mpz_cmp(*X, *Y);
}

void mpi_free( mpi *X ){
	mpz_clear(*X);
}

