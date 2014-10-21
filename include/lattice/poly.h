#ifndef POLY_H_INCLUDED
#define POLY_H_INCLUDED 
#include"polarssl/bignum.h"
#include"mont_mpi.h"

#include <math.h>  
#include "lweparam.h"
typedef  struct{
	size_t n;
	mpi **a;
	mpi *q;
}Poly_q;

typedef  struct{
	size_t n;
	int *a;
}Poly_2;

void polyAssign(Poly_q * to, Poly_q * from);
int polyWriteBuffer(Poly_q* f, void* buffer);
int polyReadBuffer(Poly_q* f, const void* buffer);
int poly2WriteBuffer(Poly_2* f, void* buffer);
int poly2ReadBuffer(Poly_2* f, const void* buffer);
void RandomPoly(Poly_q * f,  size_t n , mpi* q, float deviation, int hash, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ); //-1 for unbiased rand
void ZeroPoly(Poly_q * f,  size_t n ,mpi* q);
void ZeroPoly_2(Poly_2 * f, int n);
void polyMul(Poly_q * c, Poly_q * a, Poly_q * b);
void polyMulConst(Poly_q * c, int a, Poly_q * b);
void polyAdd(Poly_q * c, Poly_q * a, Poly_q * b);
void invFFT(Poly_q * a);
void FFT(Poly_q * a, int isign);
void Cha(Poly_2 * s, const Poly_q * a);
void Mod_2(Poly_2 * c ,const Poly_q * a ,Poly_2 * b);
void freePoly(Poly_q * f);
void freePoly2(Poly_2 * f);
int PolySize(Poly_q * f);
void init_fft();
#define FFT_FORWARD -1
#define FFT_INVERSE 1



#endif