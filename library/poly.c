#include "lattice/poly.h"
#include "stdlib.h"
#include "polarssl/bignum.h"
#include"polarssl/sha256.h"
#define polarssl_malloc malloc
#define polarssl_free free
static inline  void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}


mpi* WArray=NULL;
mpi* WinvArray=NULL;


void init_fft(){
	int i;
	if(WArray == NULL){
		WArray = polarssl_malloc ( sizeof( mpi ) * LWE_N * 2);
		WinvArray = polarssl_malloc ( sizeof( mpi ) * LWE_N * 2);
		for(i =0; i< LWE_N*2 ;i++){
			mpi_init(&WArray[i]);
			mpi_init(&WinvArray[i]);
		}		
		#include "lattice/define_fftarrays_param_1.h"
		//#include "lattice/define_fftarrays_param_3.h"
	}
}


/*
//static int randomseed=0;
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


void ntt_norm(Poly_q * f){
	size_t j;
	mpi invN;
	mpi_init(&invN);
	mpi_read_string( &invN, 10, INVN_STRING); 

	for (j = 0; j < f->n; j++){
		mpi_mont_mul(f->a[j], f->a[j], &invN);
	}
}


void rearrange(mpi** data, const size_t m) {
	size_t target = 0, position = 0, mask = m;
	mpi* t;
    //For all of input signal
    for (position = 0; position < m; ++position)
    {
        //Ignore swapped entries
        if (target > position)
        {
            //Swap
		t=data[target];	
		data[target]=data[position];
		data[position]=t;
        }

        ///Bit mask
        mask = m;
        ///While bit is set
        while (target & (mask >>= 1))
            ///Drop bit
            target &= ~mask;
        ///The current bit is 0 - set it
        target |= mask;
    }
}


void FFT(Poly_q * f, int isign){
//pr is a global mpi(define?)

	size_t m, i, j, istep, mmax;
	mpi wr, wtemp;
	mpi* FFTArray;
	int index;

	mpi_init(&wr);
	mpi_init(&wtemp);


	if (isign > 0)
		FFTArray = WinvArray;
	else
		FFTArray = WArray;

	rearrange(f->a, f->n);
	mmax = 1;
	while (f->n > mmax)	{
		istep = mmax << 1;
		index= f->n/istep;
		mpi_copy( &wr,  &FFTArray[index*2] );
		
		// Optimize first step when wr = 1
		for (i = 0; i < f->n; i += istep)
		{
			j = i + mmax;
			mpi_copy( &wtemp , f->a[j]);
			mpi_mont_sub(f->a[j], f->a[i], &wtemp );
			mpi_mont_add(f->a[i], f->a[i], &wtemp );
		}

		for (m = 1; m < mmax; m++)
		{
			for (i = m; i < f->n; i += istep)
			{
				j = i + mmax;
				mpi_mont_mul( &wtemp, &wr, f->a[j]);
				mpi_mont_sub(f->a[j], f->a[i], &wtemp );
				mpi_mont_add(f->a[i], f->a[i], &wtemp );
			}
			mpi_mont_mul(&wr, &wr, &FFTArray[index*2] );
		}
		mmax = istep;
	}

//	mpi_free(&wt);
	mpi_free(&wr);
	mpi_free(&wtemp);

}



void polyAssign(Poly_q * to, Poly_q * from){
	size_t i;
	for (i = 0 ;i < to->n;i++){
		mpi_copy(to->a[i], from->a[i]);
	}
	to->q = from->q;
}


int polyWriteBuffer(Poly_q* f, void* buf){
	size_t i;
	int qsize =mpi_size(f->q);
	for(i=0;i<f->n;i++){
		mpi_write_binary( f->a[i], buf+i*qsize , qsize );
	}
	return f->n * mpi_size(f->q);
}


int polyReadBuffer(Poly_q* f, const void* buf){
	size_t i;
	int qsize =mpi_size(f->q);
	for(i=0;i<f->n;i++){
		mpi_read_binary( f->a[i], buf+i*qsize, mpi_size(f->q));
	}
	return f->n *mpi_size(f->q);

}


int poly2WriteBuffer(Poly_2* f, void* buf){
	char * buffer = buf;
	size_t i;
	for (i =0; i < f-> n ; i++){
			*buffer=(char)f -> a[i] ;
			buffer++;
	}

	return buffer-(const  char *)buf;

}


int poly2ReadBuffer(Poly_2* f, const void* buf){
	const  char * buffer = buf;
	size_t i;
	for (i=0; i < f-> n ; i++){
			f -> a[i]  = *buffer;
			buffer++;
	}
	return buffer-(const  char *)buf;
}




static inline int myround( double r ) {
    return (r > 0.0) ? (r + 0.5) : (r - 0.5); 
}

//from http://www.codeproject.com/Articles/69941/Best-Square-Root-Method-Algorithm-Function-Precisi
float mysqrt(const float x){
  union
  {
    int i;
    float x;
  } u;
  u.x = x;
  u.i = (1<<29) + (u.i >> 1) - (1<<22); 
  
  // Two Babylonian Steps (simplified from:)
  // u.x = 0.5f * (u.x + x/u.x);
  // u.x = 0.5f * (u.x + x/u.x);
  u.x =       u.x + x/u.x;
  u.x = 0.25f*u.x + x/u.x;

  return u.x;
} 

//from http://stackoverflow.com/questions/3343395/value-of-natural-logarithm
float mylog(float x){
	int i=1;   
	float logx = 0 ;
	float ty = (x-1)/(x+1) ;
	float tty;
	do
	{
	    logx = logx + ty / i;
	    tty = ty ;
	    ty = (ty * ((x-1)/(x+1)) * ((x-1)/(x+1)));
	    i = i + 2 ;
	} while(tty - ty > 0.0000005 );

	return logx;
}

static inline double ranf(sha256_context* ctx) 
{
/*
	//remove warning
	(void) f_rng;
	(void) p_rng;
	return (((double)rand())/RAND_MAX);
*/
	unsigned int RandomMax = 0xffffffff;
	unsigned char buf[32];
	memset(buf,0,32);
	sha256_update( ctx, buf, 32 );
	return (((double)ctx->state[0])/(double)RandomMax );

}

//init+rand
void RandomPoly(Poly_q * f, size_t n , mpi* q, float deviation, int* hash, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng ){

	double x1, x2, abs;
	size_t i;
	int t;
	int RandomState[8];
	sha256_context ctx;
	
	f->n = n;
	f->a =polarssl_malloc(sizeof(mpi*)*n);
	f->q=q;

	//random sample
	//copied from http://www.taygeta.com/random/gaussian.html
	
//blame polarssl for the stupidity
	if(hash == NULL)
		f_rng(p_rng, (unsigned char *)RandomState, 32);
	else
		memcpy(RandomState, hash, 32);
	
	sha256_init( &ctx );
	sha256_starts( &ctx, 0 );
	sha256_update( &ctx, (unsigned char *)RandomState, 32 );

	for(i=0 ; i<n; i ++){
		do {
			x1 = 2.0 * ranf(&ctx) - 1.0;
			x2 = 2.0 * ranf(&ctx)  - 1.0;
			abs = x1 * x1 + x2 * x2;
		} while ( abs >= 1.0 );
	
		abs = mysqrt( (-2.0 * mylog( abs ) ) / abs );
		f->a[i]= polarssl_malloc(sizeof(mpi));
		mpi_init(f->a[i]);
		t=myround(x1 * abs * deviation);
		mpi_lset(f->a[i],  t);
		//all positive
		if( mpi_cmp_int( f->a[i], 0 ) < 0 ){
			 mpi_add_mpi( f->a[i], f->a[i], f->q );
		}
	}

//	printPoly(f);
	/*f(i)=f(i)w^i */
	for(i=0; i < f->n; i++){
		mpi_mont_trans(f->a[i]);
		mpi_mont_mul(f->a[i],f->a[i],&WArray[i]);
	}


	FFT(f,FFT_FORWARD);
	sha256_free( &ctx );
	polarssl_zeroize(RandomState, 32);
	
}

void invFFT(Poly_q * f){
	size_t i;
	mpi halve_q;
	mpi_init(&halve_q);
	mpi_copy(&halve_q, f->q );
	mpi_shift_r(&halve_q, 1);

	FFT(f,FFT_INVERSE);
	ntt_norm(f);

	/*f(i)=f(i)w^i */
	for(i=0; i < f->n; i++){
		mpi_mont_mul(f->a[i],f->a[i],&WinvArray[i]);
	}
	for(i=0;i< f->n;i++){
		mpi_mont_invtrans( f->a[i]);
	}

	for(i=0;i< f->n;i++){
		if(mpi_cmp_mpi( f->a[i], &halve_q)>0)
			mpi_sub_mpi(f->a[i], f->a[i], f->q);
	}

	mpi_free(&halve_q);


}

void ZeroPoly(Poly_q * f,  size_t n ,mpi* q){

	size_t i;
	f->n = n;
	f->a =polarssl_malloc(sizeof(mpi*)*n);
	f->q=q;
	for(i=0 ; i<n; i ++){
		f->a[i]= polarssl_malloc(sizeof(mpi));
		mpi_init(f->a[i]);
		//mpi_grow(f->a[i],f->q->n);
	}

}

void ZeroPoly_2(Poly_2 * f, int n){
	f->n = n;
	f->a =polarssl_malloc(sizeof(int)*n);
}

void polyMul(Poly_q * c, Poly_q * a, Poly_q * b){
	size_t i;
	for (i = 0 ;i <c->n;i++){
		mpi_mont_mul(c->a[i],  a->a[i], b->a[i]);
	}
}
void polyMulConst(Poly_q * c, int a, Poly_q * b){
	size_t i;
	for (i = 0 ;i < c->n ; i++){
		mpi_mont_mulconst(c->a[i],  b->a[i], a);
	}
}

void polyAdd(Poly_q * c, Poly_q * a, Poly_q * b){
	size_t i;
	for (i = 0 ;i < c->n;i++){
		mpi_mont_add(c->a[i], a->a[i], b->a[i]);
	}
}


void  Cha(Poly_2* s, const Poly_q * a){

	size_t i;
	mpi quarter_q;
	mpi_init(&quarter_q);
	mpi_copy(&quarter_q, a->q );
	mpi_shift_r(&quarter_q, 2);

	for (i = 0 ;i < s->n;i++){
		if(mpi_cmp_abs(a->a[i], &quarter_q)>0)
			s->a[i]=1;
		else
			s->a[i]=0;
	}

	mpi_free(&quarter_q);


}
void Mod_2(Poly_2 * c , const Poly_q * a ,Poly_2 * b){

	size_t i;
	mpi halve_q ,t;
	mpi_init(&halve_q);
	mpi_init(&t);
	mpi_copy(&halve_q, a->q );
	mpi_shift_r(&halve_q, 1);

	for(i=0;i< a->n;i++){
		mpi_copy(&t, a->a[i]);

		if(b->a[i]==1)
			mpi_add_mpi(&t,&t,&halve_q );

		if(mpi_cmp_mpi( &t, &halve_q)>0)
			mpi_sub_mpi(&t, &t, a->q);

		if(mpi_get_bit(&t,0)==0)
			c->a[i]=0;
		else
			c->a[i]=1;

	}

	mpi_free(&halve_q);
	mpi_free(&t);
}
void freePoly(Poly_q * f){
	//do NOT free q
	size_t i;
	for(i =0; i<f->n;i++)
		mpi_free(f->a[i]);
	free(f->a);
}

void freePoly2(Poly_2 * f){
	free(f->a);
}

int PolySize(Poly_q * f){
	//theoretically
	return f->n*mpi_size(f->q);
}







