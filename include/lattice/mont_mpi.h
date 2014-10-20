#ifndef MONT_H_INCLUDED
#define MONT_H_INCLUDED
#include "polarssl/bignum.h"
#include "lweparam.h"

void mpi_mont_mul(mpi *ROP, mpi *X, mpi* Y);
void mpi_mont_mulconst(mpi *ROP, mpi *X, int a);
void mpi_mont_add(mpi *ROP, mpi *X, mpi* Y);
void mpi_mont_sub(mpi *ROP, mpi *X, mpi* Y);
/*RR global var*/
void mpi_mont_trans( mpi *X );
void mpi_mont_invtrans( mpi *X );
void init_mont();

#endif