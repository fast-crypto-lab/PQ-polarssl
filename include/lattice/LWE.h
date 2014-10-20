#ifndef LWE_H_INCLUDED
#define LWE_H_INCLUDED

#include "poly.h"
#include "polarssl/bignum.h"
#include "lweparam.h"
#include "polarssl/dh.h"


typedef struct
{
	int srv;
    /*constant parameters, to be initialized*/
	int n;
   	float alpha;
	float beta;
	float gamma;
	//Probably shouldn't use GMP since the size of code will grow?
	//polarSSL has defined mpi but I'm unsure of the interface
	mpi* q;

	//Poly_q to be defined	
	Poly_q* a; 							/*common global variable*/
	Poly_q* pk;
	Poly_q* his_pk;					/*client pk for server, server pk for client*/
	Poly_q* sk;							/*to be calculated in initialization*/


	/*variables*/
	//Poly_q r,f,g;	 				/*defined when used*/
	Poly_q* x;
	Poly_q* r;
	Poly_q* y;
	
	//Poly_q y;						/*communication*/
	Poly_2* w;						
	Poly_2* sigma;					/*for recomputation of premaster*/
	//Poly_2* session_key;			/*length of a chosen number*/
	
    
}
lwe_context;



void lwe_init ( lwe_context  *ctx);
void *  lwe_alloc ( void ) ;
void  lwe_free ( lwe_context * ctx );
int lwe_gen_public( lwe_context *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
int lwe_compute_shared( lwe_context  *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );
int lwe_set_params ( lwe_context  *ctx, const void *params );
int lwe_read_ske( lwe_context  *ctx, int *rlen, const unsigned char *buf, size_t blen );
int lwe_read_response( lwe_context  *ctx, const unsigned char *buf, size_t blen );
size_t lwe_getsize_ske( const lwe_context *ctx );
int lwe_write_ske( size_t *olen, unsigned char *buf, size_t blen, lwe_context  *ctx );
size_t lwe_getsize_response( const lwe_context  *ctx );
int lwe_write_response( size_t *olen, unsigned char *buf, size_t blen, lwe_context  *ctx );
size_t lwe_getsize_premaster( const lwe_context  *ctx );
int lwe_write_premaster( size_t *olen, unsigned char *buf, size_t blen, const lwe_context  *ctx );




#endif