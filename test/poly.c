//looks like I'll have to expand mulmod and addmod myself
//but mod... q is in {-q/2, q/2}, not{0,q}

#include "poly.h"
#include "stdlib.h"
#include "bignum.h"
#include <math.h>
#define polarssl_malloc malloc
#define polarssl_free free

static int randomseed=0;

void ntt_norm(Poly_q * f){

	mpi w;
	mpi_init(&w);
	mpi_lset(&w, f->n);
	mpi_inv_mod( &w, &w, f->q );
	int j;
	for (j = 0; j < f->n; j++){
		mpi_mul_mpi(f->a[j], f->a[j], &w);
		mpi_mod_mpi(f->a[j], f->a[j], f->q);
//		mpi_shrink( f->a[j], f->q->n);
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
	mpi w, wt, wr, wtemp;
	mpi t, t2;

	mpi_init(&w);	
	mpi_init(&wt);
	mpi_init(&wr);
	mpi_init(&wtemp);
	mpi_init(&t);
	mpi_init(&t2);


	mpi_sub_int(&t2, f->q, 1 );
	mpi_div_int(&t, NULL, &t2, f->n);

	if (isign > 0){
		mpi_sub_mpi(&t,&t2,&t);
	}
	else
		;

	mpi_lset(&t2, PROOT);
	mpi_exp_mod(&w , &t2, &t, f->q, NULL);

	rearrange(f->a, f->n);

	mmax = 1;
	while (f->n > mmax)
	{
		istep = mmax << 1;
		mpi_lset(&t, f->n );
		mpi_lset(&t2,istep);
		mpi_div_mpi(&t, NULL, &t, &t2);
		mpi_exp_mod(&wt , &w, &t, f->q, NULL);
		mpi_copy( &wr, &wt);
		
		// Optimize first step when wr = 1
		for (i = 0; i < f->n; i += istep)
		{
			j = i + mmax;
			mpi_copy( &wtemp , f->a[j]);
			mpi_sub_mpi(f->a[j], f->a[i], &wtemp );
			mpi_add_mpi(f->a[i], f->a[i], &wtemp );
			mpi_mod_mpi(f->a[i], f->a[i], f->q);
			mpi_mod_mpi(f->a[j], f->a[j], f->q);
		}

		for (m = 1; m < mmax; m++)
		{
			for (i = m; i < f->n; i += istep)
			{
				j = i + mmax;
				mpi_mul_mpi( &wtemp, &wr, f->a[j]);
				mpi_mod_mpi(&wtemp, &wtemp, f->q);
				mpi_sub_mpi(f->a[j], f->a[i], &wtemp );
				mpi_add_mpi(f->a[i], f->a[i], &wtemp );
				mpi_mod_mpi(f->a[i], f->a[i], f->q);
				mpi_mod_mpi(f->a[j], f->a[j], f->q);
			}
			mpi_mul_mpi(&wr, &wr, &wt);
			mpi_mod_mpi(&wr, &wr, f->q);
		}
		mmax = istep;
	}
}



void polyAssign(Poly_q * to, Poly_q * from){
	int i;
	for (i = 0 ;i < to->n;i++){
		mpi_copy(to->a[i], from->a[i]);
	}
	mpi_copy(to->q, from->q);
}


int polyWriteBuffer(Poly_q* f, void* buf){
	int i;
	int qsize =mpi_size(f->q);
	for(i=0;i<f->n;i++){
		mpi_write_binary( f->a[i], buf+i*qsize , qsize );
	}
	return f->n * mpi_size(f->q);
}


int polyReadBuffer(Poly_q* f, const void* buf){
	int i;
	for(i=0;i<f->n;i++){
		mpi_read_binary( f->a[i], buf+i* mpi_size(f->q), mpi_size(f->q));
	}
	return f->n *mpi_size(f->q);

}




/*
int polyWriteBuffer(Poly_q* f, void* buf){
	int * buffer = buf;
	int len=0;
	int i,j;
	for(i=0;i<f->n;i++){
		for(j=0;j< f->q->n;j++){
			*buffer =f->a[i]->p[j];
			buffer++;
			//buffer[i*f->q->n+j] = f->a[i]->p[j];
			len++;
		}
	}
	//to be optimized
	//return (buffer - (int*)buf)*sizeof(int);
	return len*sizeof(int);

}


int polyReadBuffer(Poly_q* f, const void* buf){
	int * buffer = buf;
	int len=0;
	int i,j;
	for(i=0;i<f->n;i++){
		for(j=0;j<f->q->n;j++){
			f->a[i]->p[j]= *buffer ;
			buffer++;
			//buffer[i*f->q->n+j] = f->a[i]->p[j];
			len++;
		}
	}
	//to be optimized
	//return (buffer - (int*)buf)*sizeof(int);
	return len*sizeof(int);

}
*/

int poly2WriteBuffer(Poly_2* f, void* buf){
	char * buffer = buf;
	int len=0;
	int i;
	for (i =0; i < f-> n ; i++){
			*buffer=(char)f -> a[i] ;
			buffer++;
			len++;
	}

	//to be optimized
	//return (buffer - (int*)buf)*sizeof(int);
	return len*sizeof(char );

}


int poly2ReadBuffer(Poly_2* f, const void* buf){
	char * buffer = buf;
	int len=0;
	int i;
	for (i=0; i < f-> n ; i++){
			f -> a[i]  = *buffer;
			buffer++;
			len++;
	}
	//to be optimized
	//return (buffer - (int*)buf)*sizeof(int);
	return len*sizeof(char );

}







//copied from bignum.c
#define ciL	(sizeof(t_uint))		 /* chars in limb  */
#define biL	(ciL << 3)			   /* bits  in limb  */
#define biH	(ciL << 2)			   /* half limb size */

double ranf()
{
  return (((double)rand())/RAND_MAX);
}

//init+rand
void RandomPoly(Poly_q * f, int n , mpi* q, float deviation, int hash){

	f->n = n;
	f->a =polarssl_malloc(sizeof(mpi*)*n);
	f->q=q;

//	f->q =polarssl_malloc(sizeof(mpi));
//	mpi_init(f->q);
//	mpi_copy(f->q, q);

	//random sample
	//copied from http://www.taygeta.com/random/gaussian.html

	double x1, x2, abs;
	int i;
	
/*
	printf("%f", deviation);
	exit(0);
*/
		
	if(hash == NULL){
	 	srand(randomseed);
		randomseed++;
	}
	else
		srand(hash);

	for(i=0 ; i<n; i ++){
		do {
			x1 = 2.0 * ranf() - 1.0;
			x2 = 2.0 * ranf() - 1.0;
			abs = x1 * x1 + x2 * x2;
		} while ( abs >= 1.0 );

	
		abs = sqrt( (-2.0 * log( abs ) ) / abs );
		f->a[i]= polarssl_malloc(sizeof(mpi));
		mpi_init(f->a[i]);
		int t=round(x1 * abs * deviation);
		mpi_lset(f->a[i],  t);
		//all positive
		if( mpi_cmp_int( f->a[i], 0 ) < 0 )
			 mpi_add_mpi( f->a[i], f->a[i], f->q );
		
		//printf("%f %d\n", (x1 * abs * deviation), t);

	}

	//exit(0);



	//likely to be slow as hell
	mpi t,w;
	mpi_init(&t);
	mpi_init(&w);
	mpi_lset(&w, PROOT);
	
	mpi_sub_int(&t, f->q, 1 );
	mpi_div_int(&t, NULL, &t, f->n*2);
	mpi_exp_mod(&w , &w, &t, f->q, NULL);
	mpi_lset(&t, 1);

	/*f(i)=f(i)w^i */
	for(i=0; i < f->n; i++)	{
		mpi_mul_mpi(f->a[i],f->a[i],&t);
		mpi_mul_mpi(&t,&t,&w);
		mpi_mod_mpi(f->a[i], f->a[i], f->q);
		mpi_mod_mpi(&t, &t, f->q);

	}
/*
	char  buffer2[80];
	for(i=0; i<2048; i++){
		mpi_write_file( NULL, (f->a[i]) , 10, NULL );
	}

	exit (0);
*/

	FFT(f,FFT_FORWARD);

}

void ZeroPoly(Poly_q * f, int n ,mpi* q){
	f->n = n;
	f->a =polarssl_malloc(sizeof(mpi*)*n);
	f->q=q;


	int i;
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
	// check of n is ignored
	int i ;
	for (i = 0 ;i <c->n;i++){
		mpi_mul_mpi(c->a[i],  a->a[i], b->a[i] );
		mpi_mod_mpi(c->a[i], c->a[i], c->q);
//		mpi_shrink( c->a[i], c->q->n);
	}
}
void polyMulConst(Poly_q * c, int a, Poly_q * b){
	int i ;
	for (i = 0 ;i < c->n ; i++){
		mpi_mul_int(c->a[i], b->a[i], a);
		mpi_mod_mpi(c->a[i], c->a[i], c->q);
//		mpi_shrink( c->a[i], c->q->n);
	}
}

void polyAdd(Poly_q * c, Poly_q * a, Poly_q * b){
	int i ;
	for (i = 0 ;i < c->n;i++){
		mpi_add_mpi(c->a[i], a->a[i], b->a[i]);
		mpi_mod_mpi(c->a[i], c->a[i], c->q);
//		mpi_shrink( c->a[i], c->q->n);
	}
}

void invFFT(Poly_q * f){
//
	mpi t,w;
	mpi_init(&t);
	mpi_init(&w);
	int i;

	FFT(f,FFT_INVERSE);



	ntt_norm(f);

	/*f(i)=f(i)w^-i*/

	mpi_lset(&w, PROOT);
	mpi_sub_int(&t, f->q, 1 );
	mpi_div_int(&t, NULL, &t, f->n*2);
	mpi_exp_mod(&w , &w, &t, f->q, NULL);
	mpi_inv_mod( &w, &w, f->q );
	mpi_lset(&t, 1);

	/*f(i)=f(i)w^i */

	for(i=0; i < f->n; i++)	{
		mpi_mul_mpi(f->a[i],f->a[i],&t);
		mpi_mul_mpi(&t,&t,&w);
		mpi_mod_mpi(f->a[i], f->a[i], f->q);
		mpi_mod_mpi(&t, &t, f->q);
//		mpi_shrink( f->a[i], f->q->n);
	}
}



void  Cha(Poly_2* s, const Poly_q * a){

	int i;
	mpi quarter_q, halve_q;
	mpi_init(&quarter_q);
	mpi_init(&halve_q);

	mpi_div_int( &halve_q, NULL, a->q, 2 );
	mpi_div_int( &quarter_q, NULL, &halve_q, 2 );

	Poly_q f;
	ZeroPoly(&f, a->n ,a->q);

	for(i=0;i< a->n;i++){
		if(mpi_cmp_mpi( f.a[i], &halve_q)==1)
			mpi_sub_mpi( f.a[i], a->a[i], a->q);
		else
			mpi_copy(f.a[i], a->a[i]);
	}

	for (i = 0 ;i < s->n;i++){
		if(mpi_cmp_abs(f.a[i], &quarter_q)==1)
			s->a[i]=1;
		else
			s->a[i]=0;
	}

	freePoly(&f);
	mpi_free(&halve_q);
	mpi_free(&quarter_q);


}
void Mod_2(Poly_2 * c , const Poly_q * a ,Poly_2 * b){


	mpi halve_q ,t;
	mpi_init(&halve_q);
	mpi_init(&t);
	mpi_div_int( &halve_q, NULL, a->q, 2 );

	int i;
	Poly_q f;
	ZeroPoly(&f, a->n ,a->q);

	for(i=0;i< a->n;i++){
		if(mpi_cmp_mpi( f.a[i], &halve_q)==1)
			mpi_sub_mpi( f.a[i], a->a[i], a->q);
		else
			mpi_copy(f.a[i], a->a[i]);
	}/*could be optimized*/

	for(i=0;i< a->n;i++){
		mpi_copy(&t, f.a[i]);

		if(b->a[i]==1)
			mpi_add_mpi(&t,&t,&halve_q );

		mpi_div_int( NULL, &t, &t, 2 );
		if(mpi_cmp_int(&t,0)==0)
			c->a[i]=0;
		else
			c->a[i]=1;

	}

	freePoly(&f);
	mpi_free(&halve_q);
}
void freePoly(Poly_q * f){
	//do NOT free q
	int i;
	for(i =0; i<f->n;i++)
		mpi_free(f->a[i]);
	free(f->a);
//	mpi_free(f->q);
//	free(f);
}

void freePoly2(Poly_2 * f){
	free(f->a);
//	free(f);
}

int PolySize(Poly_q * f){
	//theoretically
	return f->n*mpi_size(f->q);
}





