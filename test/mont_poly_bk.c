//looks like I'll have to expand mulmod and addmod myself
//but mod... q is in {-q/2, q/2}, not{0,q}
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/
/*adandon montgomery!!!*/


FFT(Poly_q * f, isign)(mpz_class *data, const size_t nn, const mpz_class pr, mpz_class q, const int isign){
//pr is a global mpi

	size_t m, i, j, istep, mmax;
	mpi w, wt, wr, wtemp;
	mpi t, t2;

	mpi_init(&w)...


	mpi_sub_int(&t2, f->q, 1 );
	mpi_div_int(&t, NULL, &t2, f->n/*2 times?*/)

	if (isign > 0)
		mpi_sub_mpi(&t,&t2,&t);
	else
		;

	mpi_exp_mod(&w , &pr, &t, f->q, NULL);

	rearrange(f->a, f->n);

	mmax = 1;
	while (f->n > mmax)
	{
		istep = mmax << 1;
		t= (mpz_class)nn / (mpz_class)istep;//??

		mpi_exp_mod(&wt , &w, &t, f->q, NULL);
		mpi_copy( &wr, &wt);
		
		// Optimize first step when wr = 1
		for (i = 0; i < nn; i += istep)
		{
			j = i + mmax;
			mpi_copy( &wtemp , f->a[j]);
			mpi_sub_mpi(f->a[j], f->a[i], &wtemp );
			mpi_add_mpi(f->a[i], f->a[i], &wtemp );
			if( mpi_cmp_int( f->a[j], 0 ) < 0 )
				MPI_CHK( mpi_add_mpi( f->a[j], f->a[j], f->q ) );
			if( mpi_cmp_int( f->a[i], f->q ) >= 0 )
				MPI_CHK( mpi_sub_mpi( f->a[i], f->a[i], f->q ) );

		}

		for (m = 1; m < mmax; m++)
		{
			for (i = m; i < nn; i += istep)
			{
				j = i + mmax;
				mpi_copy( &wtemp , f->a[j]);
				
				wtemp = (wr * data[j])%q;
				data[j] = (data[i] - wtemp+q)%q;
				data[i] = (data[i]+wtemp)%q;
			}
			wr = (wr *wt)%q;
		}
		mmax = istep;
	}
}



void polyAssign(Poly_q * to, Poly_q * from)/*for a*/{
	for (int i = 0 ;i < to->n;i++){
		mpi_copy(to->a[i], from->a[i]);
	}
}

//copied from bignum.c
#define ciL	(sizeof(t_uint))		 /* chars in limb  */
#define biL	(ciL << 3)			   /* bits  in limb  */
#define biH	(ciL << 2)			   /* half limb size */


/* Fast Montgomery initialization (thanks to Tom St Denis) */
static void mpi_montg_init( t_uint *mm, const mpi *N )
{
	t_uint x, m0 = N->p[0];
	unsigned int i;

	x  = m0;
	x += ( ( m0 + 2 ) & 4 ) << 1;

	for( i = biL; i >= 8; i /= 2 )
		x *= ( 2 - ( m0 * x ) );

	*mm = ~x + 1;
}

/* Montgomery multiplication: C = A * B * R^-1 mod N  */
static void mpi_montmul( mpi *C ,const mpi *A, const mpi *B, const mpi *N, t_uint mm,const mpi *T ){
	size_t i, n, m;
	t_uint u0, u1, *d;

	memset( T->p, 0, T->n * ciL );

	d = T->p;
	n = N->n;
	m = ( B->n < n ) ? B->n : n;

	for( i = 0; i < n; i++ )
	{
		/*
		 * T = (T + u0*B + u1*N) / 2^biL
		 */
		u0 = A->p[i];
		u1 = ( d[0] + u0 * B->p[0] ) * mm;

		mpi_mul_hlp( m, B->p, d, u0 );
		mpi_mul_hlp( n, N->p, d, u1 );

		*d++ = u0; d[n + 1] = 0;
	}

	memcpy( C->p, d, ( n + 1 ) * ciL );

	if( mpi_cmp_abs( A, N ) >= 0 )
		mpi_sub_hlp( n, N->p, C->p );
	else
		/* prevent timing attacks */
		mpi_sub_hlp( n, C->p, T->p );

}


/*
 * Montgomery reduction: C = A * R^-1 mod N
 */
static void mpi_montred( mpi *C, const  mpi *A, const mpi *N, t_uint mm, const mpi *T )
{
	t_uint z = 1;
	mpi U;

	U.n = U.s = (int) z;
	U.p = &z;

	mpi_montmul( C, A, &U, N, mm, T );
}

inv_mont(Poly_q* a){
	for(int i=0 ; i<a->n; i ++){
		mpi_montred(a->a[i], a->a[i], a->q, a->mm,a->T);
	}
}

double ranf()
{
  return (((double)rand())/RAND_MAX);
}


RandomPoly(Poly_q * f, int n , mpi* q, float deviation, int hash = -1){//init+rand

	f->n = n;
	f->a =polarssl_malloc(sizeof(mpi*)*n);
	f->q=q;


	//random sample
	//copied from http://www.taygeta.com/random/gaussian.html

	double x1, x2, w;
	
	if(hash == -1)
	 	srand(time(0));
	else
		srand(hash);

	for(int i=0 ; i<n; i ++){
		do {
			x1 = 2.0 * ranf() - 1.0;
			x2 = 2.0 * ranf() - 1.0;
			w = x1 * x1 + x2 * x2;
		} while ( w >= 1.0 );

	
		w = sqrt( (-2.0 * ln( w ) ) / w );
		f->a[i]= polarssl_malloc(sizeof(mpi));
		mpi_init(f->a[i]);
		mpi_lset(f->a[i], round(x1 * w * deviation) );
		//all positive
		if( mpi_cmp_int( f->a[i], 0 ) < 0 )
			MPI_CHK( mpi_add_mpi( f->a[i], f->a[i], f->q ) );
		
	}
	//montgomery

	int ret;
	size_t wbits, wsize, one = 1;
	size_t i, j, nblimbs;
	size_t bufsize, nbits;
	t_uint mm;
	mpi RR;
	mpi_montg_init( &mm, N );
	f->mm = mm; //should always have the same value

	f->t= polarssl_malloc(sizeof(mpi));
	mpi_init( f->T );//not sure if keeping a computation space will make it faster?
	mpi_init( &RR ); 

	MPI_CHK( mpi_lset( &RR, 1 ) );
	MPI_CHK( mpi_shift_l( &RR, q->n * 2 * biL ) );
	MPI_CHK( mpi_mod_mpi( &RR, &RR, q));//i wouldn't dare use this... maybe precomute somewhere else

	for (int i = 0 ;i < f->n;i++){
		mpi_montmul(f->a[i],  f->a[i], &RR, f->q, f->mm, f->T );
	}

	FFT(f);

}

ZeroPoly(Poly_q * f, int n ,mpi* q){
	f->n = n;
	f->a =polarssl_malloc(sizeof(mpi*)*n);
	f->q=q;
	for(int i=0 ; i<n; i ++)
		f->a[i]= polarssl_malloc(sizeof(mpi));

}
ZeroPoly_2(Poly_2 * f, int n){
	f->n = n;
	f->a =polarssl_malloc(sizeof(int));
}

polyMul(Poly_q * c, Poly_q * a, Poly_q * b){
	// check of n is ignored

	for (int i = 0 ;i < a->n;i++){
		mpi_montmul(c->a[i],  a->a[i], b->a[i] , c->q, c->mm, c->T );
		mpi_shrink( c->a[i], c->q->n);
	}
}
polyMulConst(Poly_q * c, int a, Poly_q * b)
{
	for (int i = 0 ;i < a->n;i++){
		mpi_mul_int(c->a[i], b->a[i], a);
		mpi_mod_mpi(c->a[i], c->a[i], c->q);
		mpi_shrink( c->a[i], c->q->n);
	}
}

polyAdd(Poly_q * c, Poly_q * a, Poly_q * b){

	for (int i = 0 ;i < a->n;i++){
		mpi_add_mpi(c->a[i], a->a[i], b->a[i])
		mpi_mod_mpi(c->a[i], c->a[i], c->q);
		mpi_shrink( c->a[i], c->q->n);
	}
}

invFFT(Poly_q * a){
//

//
	inv_mont(a);

}



Poly_2 Cha(Poly_2* s, Poly_q * a){
	mpi* quarter_q = polarssl_malloc ( sizeof( mpi) );
	mpi_init(quarter_q);
	mpi_div_int( quarter_q, NULL, a->q, 2 );
	mpi_div_int( quarter_q, NULL, quarter_q, 2 );

	for (int i = 0 ;i < a->n;i++){
		if(mpi_cmp_abs(a->a[i], quarter_q))
			s->a[i]=1;
		else
			s->a[i]=0;
	}

}
Mod_2(Poly_2 * c ,Poly_q * a ,Poly_2 * b){


	mpi* halve_q = polarssl_malloc ( sizeof( mpi) );
	mpi_init(halve_q);
	mpi_div_int( halve_q, NULL, a->q, 2 );

	mpi* t = polarssl_malloc ( sizeof( mpi) );
	mpi_init(t);
	
	for (int i = 0 ;i < a->n;i++){
		mpi_copy(t, a->a[i]);
		if(b->a[i]==1)
			mpi_add_mpi(t,t,halve_q );

		if(mpi_get_bit(t,0)==0)
			c->a[i]=0;
		else
			c->a[i]=1;
	}


}
freePoly(Poly_2 * a);