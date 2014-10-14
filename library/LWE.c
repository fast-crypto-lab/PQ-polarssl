#include"lattice/LWE.h"
#include"polarssl/sha256.h"
#include "stdlib.h"
#define polarssl_malloc malloc
#define polarssl_free free

#include <sys/time.h>
static double get_ms_time(void) {
	struct timeval timev;

	gettimeofday(&timev, NULL);
	return (double) timev.tv_sec * 1000 + (double) timev.tv_usec / 1000;
}




/*
static void printPoly(Poly_q * f){
	//invFFT(f);
	int i;
	char  buffer2[80];
	for(i=0; i<f->n; i++){
		mpz_get_str(buffer2, 10, *(f->a[i]));
		printf("%s\n", buffer2);
	}
}
*/
void lwe_init( lwe_context  *ctx) {

	ctx->n = LWE_N;
	ctx->alpha = LWE_ALPHA;
	ctx->beta = LWE_BETA;		
	ctx->gamma = LWE_GAMMA;
	ctx->q = polarssl_malloc ( sizeof( mpi ) );
	mpi_init(ctx->q );
	mpi_read_string( ctx->q, 10,  Q_STRING);
	init_mont();
	init_fft();

	ctx->a  =polarssl_malloc ( sizeof( Poly_q) );
	ZeroPoly(ctx ->a,ctx ->n,ctx ->q);

//	#include "polynomial_a_param_3.h"
	#include "lattice/polynomial_a_param_1.h"

	Poly_q* e = polarssl_malloc ( sizeof( Poly_q) );
	ctx->pk = polarssl_malloc ( sizeof( Poly_q) );
	ctx->sk = polarssl_malloc ( sizeof( Poly_q) );
	ZeroPoly(ctx ->pk,ctx ->n,ctx ->q);
	RandomPoly(ctx->sk, ctx->n, ctx->q, ctx->alpha, -1);
	RandomPoly(e,	ctx->n, ctx->q, ctx->alpha, -1);

	polyMul(ctx->pk ,ctx->sk, ctx->a);
/*
	invFFT(ctx->a);
	printPoly(ctx->a);
	exit(0);
*/


	polyMulConst( e, 2, e);
	polyAdd(ctx->pk , ctx->pk , e  );


	
}
	



void *  lwe_alloc ( void ) {
    lwe_context *ctx = polarssl_malloc( sizeof( lwe_context ) );

    if( NULL ==  ctx ) {
        return NULL;
    }

    lwe_init(ctx);
    return ctx;

}

void  lwe_free ( lwe_context * ctx ) {
    //free all the poly
	freePoly(ctx->sk);
	freePoly(ctx->pk);
	freePoly(ctx->his_pk);
	freePoly(ctx->a);
	freePoly(ctx->x);
	freePoly(ctx->r);
	freePoly(ctx->y);
	freePoly2(ctx->w);

}

int lwe_gen_public( lwe_context *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{//server and client must compute different things, how to implement.

    return 0;
}


int lwe_compute_shared ( lwe_context  *ctx, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ){
	//maybe some assignment;

	return 0;
}
int lwe_set_params ( lwe_context  *ctx, const void *params ){
	
	return 0;
}



int lwe_read_ske( lwe_context  *ctx, int *rlen, const unsigned char *buf, size_t blen ){
/*disabled debug
    if (blen < 2 || blen > 2*ctx -> n * mpi_size( ctx ->q) ) {
        return POLARSSL_ERR_DHM_BAD_INPUT_DATA;
    }
*/
	//alloc x, his_pk
	ctx ->x = polarssl_malloc ( sizeof( Poly_q) );
	ctx ->his_pk = polarssl_malloc ( sizeof( Poly_q) );
	ZeroPoly(ctx ->x,ctx ->n,ctx ->q);
	ZeroPoly(ctx ->his_pk ,ctx ->n,ctx ->q);

	//x
	*rlen = polyReadBuffer(ctx ->x, buf);
	//his_pk
	*rlen += polyReadBuffer(ctx ->his_pk, buf + *rlen);

}


int lwe_read_response( lwe_context  *ctx, const unsigned char *buf, size_t blen ){
	//receive

	//alloc y,w,his_pk
	ctx ->his_pk = polarssl_malloc ( sizeof( Poly_q) );
	ctx ->y = polarssl_malloc ( sizeof( Poly_q) );
	ctx ->w = polarssl_malloc ( sizeof( Poly_2) );
	ZeroPoly(ctx ->y,ctx->n,ctx->q);
	ZeroPoly_2(ctx ->w,ctx->n);
	ZeroPoly(ctx ->his_pk, ctx->n,ctx->q);

	int rlen;
	//y
	rlen = polyReadBuffer(ctx ->y, buf);
	//pk
	rlen += polyReadBuffer(ctx ->his_pk, buf + rlen);
	//w(poly_2)
	rlen += poly2ReadBuffer(ctx ->w, buf + rlen);


//cheat

	Poly_q* g = polarssl_malloc ( sizeof( Poly_q) );
	RandomPoly(g,ctx->n, ctx->q, ctx->beta, -1);



	Poly_q* c = polarssl_malloc ( sizeof( Poly_q) );
	Poly_q* d = polarssl_malloc ( sizeof( Poly_q) );

	int hash[8];
	int bufferlength =PolySize(ctx ->x);//i,j is ignored
	char* buffer = polarssl_malloc(bufferlength );
	polyWriteBuffer(ctx ->x, buffer);
	sha256(buffer ,bufferlength  ,(char *)hash ,0);
	RandomPoly(c, ctx->n, ctx->q, ctx->gamma,  hash[0]);
	polarssl_free(buffer);

	bufferlength = PolySize(ctx ->x)+PolySize(ctx ->y);
	buffer = polarssl_malloc(bufferlength );
	polyWriteBuffer(ctx ->y, buffer);
	polyWriteBuffer(ctx ->x, buffer + PolySize(ctx ->y));
	sha256(buffer ,bufferlength  ,(char *)hash ,0);
	RandomPoly(d, ctx->n, ctx->q, ctx->gamma,  hash[0]);
	polarssl_free(buffer);


	polyMul(d, ctx ->his_pk, d );
	polyMul(c, ctx ->sk, c );
	polyAdd(d, d, ctx ->y);
	polyAdd(c, c, ctx ->r );
	
	polyMul(d,c,d);
	polyMulConst( g, 2, g);
	polyAdd(d, d, g );

	invFFT(d);
	Mod_2(ctx ->w, d ,ctx ->w);

	freePoly(g);
	freePoly(c);
	freePoly(d);
	
}



size_t  lwe_getsize_ske( const lwe_context *ctx ){
	//return size of message sent
	//poly_q*2
	return  PolySize(ctx ->pk)*2;
}

int lwe_write_ske( size_t *olen, unsigned char *buf, size_t blen, lwe_context  *ctx ){

	//cheat

	ctx ->r = polarssl_malloc ( sizeof( Poly_q) );
	ctx ->x = polarssl_malloc ( sizeof( Poly_q) );
	Poly_q* f = polarssl_malloc ( sizeof( Poly_q) );
	RandomPoly(ctx ->r,	ctx->n, ctx->q, ctx->beta, -1);
	RandomPoly(f,			ctx->n, ctx->q, ctx->beta, -1);
	ZeroPoly(ctx ->x,ctx->n,ctx->q);

	polyMul(ctx->x ,ctx->r, ctx->a);
	polyMulConst( f, 2, f);
	polyAdd(ctx->x , ctx->x , f  );



/*
	if( ctx == NULL || blen < wdhm_getsize_params(ctx) )
		return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );
*/

	//x
	*olen = polyWriteBuffer(ctx ->x, buf);
	//pk
	*olen += polyWriteBuffer(ctx ->pk , buf+*olen );

	freePoly(f);
	return 0;

}

size_t lwe_getsize_response( const lwe_context  *ctx ){
	//poly_q*2+poly_2
	return PolySize(ctx ->pk)*2+(ctx->n)*4;
}

int lwe_write_response( size_t *olen, unsigned char *buf, size_t blen, lwe_context  *ctx ){
	//cheat

double time1 = get_ms_time();

	ctx ->r = polarssl_malloc ( sizeof( Poly_q) );
	ctx ->y = polarssl_malloc ( sizeof( Poly_q) );
	Poly_q* f = polarssl_malloc ( sizeof( Poly_q) );
	RandomPoly(ctx ->r,	ctx->n, ctx->q, ctx->beta, -1);
	RandomPoly(f,			ctx->n, ctx->q, ctx->beta, -1);
	ZeroPoly(ctx ->y,ctx->n,ctx->q);

double time2 = get_ms_time();

	polyMul(ctx->y ,ctx->r, ctx->a);
	polyMulConst( f, 2, f);
	polyAdd(ctx->y , ctx->y , f  );

double time3 = get_ms_time();

	Poly_q* c = polarssl_malloc ( sizeof( Poly_q) );
	Poly_q* d = polarssl_malloc ( sizeof( Poly_q) );
	Poly_q* g = polarssl_malloc ( sizeof( Poly_q) );
	RandomPoly(g,	 ctx->n, ctx->q, ctx->beta, -1);

	int hash[8];
	int bufferlength =PolySize(ctx ->x);//i,j is ignored
	char* buffer = polarssl_malloc(bufferlength );
	polyWriteBuffer(ctx ->x, buffer);
	sha256(buffer ,bufferlength  ,(char *)hash ,0);
	RandomPoly(c, ctx->n, ctx->q, ctx->gamma,   hash[0]);
	polarssl_free(buffer);


	bufferlength = PolySize(ctx ->x)+PolySize(ctx ->y);
	buffer = polarssl_malloc(bufferlength );
	polyWriteBuffer(ctx ->y, buffer);
	polyWriteBuffer(ctx ->x, buffer + PolySize(ctx ->y) );
	sha256(buffer ,bufferlength,(char *)hash ,0);
	RandomPoly(d, ctx->n, ctx->q, ctx->gamma,  hash[0]);
	polarssl_free(buffer);

double time4 = get_ms_time();

	polyMul(c, c, ctx->his_pk);
	polyMul(d, d, ctx->sk);
	polyAdd(c,c,ctx->x);
	polyAdd(d,d,ctx ->r);
	polyMul(c, d, c);
	polyMulConst(g, 2, g);
	polyAdd(g ,c, g);

double time5 = get_ms_time();


	ctx ->w = polarssl_malloc ( sizeof( Poly_2) );
	ZeroPoly_2(ctx ->w,ctx->n);

	invFFT(g);

double time6 = get_ms_time();

	Cha(ctx ->w ,g);

double time7 = get_ms_time();
	//write y,w,pk

//	if( ctx == NULL || blen < wdhm_getsize_response(ctx) )
//		return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );

	//probably will go wrong, since mpi doesn't properly cleanup.
	//x
	*olen = polyWriteBuffer(ctx ->y, buf);
	//pk
	*olen += polyWriteBuffer(ctx ->pk , buf+*olen );
	//w
	*olen += poly2WriteBuffer(ctx ->w , buf+*olen );
double time8 = get_ms_time();

//compute the rest

	Mod_2(ctx ->w, g ,ctx ->w);

double time9 = get_ms_time();

	freePoly(c);
	freePoly(d);
	freePoly(g);
	freePoly(f);

	printf("alloc poly*2 %f ms\n", time2- time1);
	printf("compute y %f ms\n", time3- time2);
	printf("hash*2 and alloc poly*3 %f ms\n", time4- time3);
	printf("compute g %f ms\n", time5- time4);
	printf("invfft %f ms\n", time6- time5);
	printf("cha %f ms\n", time7- time6);
	printf("writebuffer %f ms\n", time8- time7);
	printf("mod_2 %f ms\n", time9- time8);


}

size_t lwe_getsize_premaster( const lwe_context  *ctx ){
    return ctx->n;
}

int lwe_write_premaster( size_t *olen, unsigned char *buf, size_t blen, const lwe_context  *ctx ){
/*
    if( ctx == NULL || blen < ctx->n )
        return( POLARSSL_ERR_DHM_BAD_INPUT_DATA );
*/
	//write w
	*olen = poly2WriteBuffer(ctx ->w , buf );
	return 0;
}





const dh_info2_t lwe_info = {
    POLARSSL_DH_LWE,
    "M_LWE",
    lwe_alloc,
    lwe_free,
    lwe_gen_public,
    lwe_compute_shared,
    lwe_set_params,
    lwe_read_ske,
    lwe_read_response,
    NULL,
    NULL,
    lwe_getsize_ske,
    lwe_write_ske,
    lwe_getsize_response,
    lwe_write_response,
    lwe_getsize_premaster,
    lwe_write_premaster,
};











































