#define __POLARSSL__

#if defined(__POLARSSL__)
#include "rainbow_tts/run_config.h"
#include "rainbow_tts/linear31.h"
#else
#include "run_config.h"
#include "linear31.h"
#endif


/* ==================== */

#if defined(__CRYPTO_EBATS__)
#include "randombytes.h"
#else
#include <stdlib.h>
static void randombytes(uint8_t *r,size_t s)
{
        unsigned i;
        for(i=0;i<s;i++) r[i]=rand();
}
#endif



int dummy_rng(void *state,unsigned char * bytes , size_t len )
{
	((void)state);
	randombytes(bytes,len);
	return 0;
}


void vec_rand( uint8_t * vec , unsigned len , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	unsigned i,j;
	uint8_t gftmp[6];
	uint32_t tmp = 0;
	for(i=0;i<len;i+=6){
		f_rng(p_rng,(unsigned char*)&tmp,4);
		/*randombytes((uint8_t *)&tmp,3);*/
		cvt_31x6p5_bin32( gftmp , tmp );
		for(j=0;j<6;j++) {
			if(i+j>=len) break;
			vec[i+j]=gftmp[j];
		}
	}
}

/* ===================== */




void vec_assign32( uint32_t * r , const uint8_t * inp , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) r[i] = inp[i];
}

void vec_assign( uint8_t * r , const uint8_t * inp , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) r[i] = inp[i];
}




inline static void vec_fastreduce32( uint8_t * r , const uint32_t * inp , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) r[i] = fast_mod31_32( inp[i] );
}


void vec_fullreduce32_cvt( uint8_t * r , const uint32_t * inp , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) r[i] = full_mod31_32( inp[i] );
}



void vec_fullreduce( uint8_t * r , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) {
		r[i] = remove_31( (r[i]>>5)+(r[i]&0x1f) );
	}
}






inline static void vec_mul32( uint32_t * r , const uint8_t * vec , unsigned c , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) r[i] = c * ((unsigned)vec[i]);
}

inline static void vec_mad32( uint32_t * accu_r , const uint8_t * vec , unsigned c , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) accu_r[i] += c*((unsigned)vec[i]);
}

inline static void vec_mad3232( uint32_t * accu_r , const uint32_t * vec , unsigned c , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) accu_r[i] += c*vec[i];
}



void vec_negative( uint8_t * r , const uint8_t * frd_vec , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) r[i] = negative_31( frd_vec[i] );
}

void vec_add( uint8_t * accu_r , const uint8_t * vec , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) accu_r[i] += vec[i];
}



uint8_t vec_dot( const uint8_t * vec1 , const uint8_t * vec2 , unsigned len )
{
	unsigned rr=0;
	unsigned i;
	for(i=0;i<len;i++) rr += ((unsigned)vec1[i])*((unsigned)vec2[i]);
	return full_mod31_32( rr );
}


void mat_mad32( uint32_t * accu_r , const uint8_t * mat , const uint8_t * vec , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) vec_mad32( accu_r , mat + len*i , vec[i] , len );
}




inline static uint8_t vec_dot32( const uint32_t * vec1 , const uint8_t * vec2 , unsigned len )
{
	unsigned rr=0;
	unsigned i;
	for(i=0;i<len;i++) rr += ((unsigned)vec1[i])*((unsigned)vec2[i]);
	return full_mod31_16( rr );
}


void rowmat_mul32( uint8_t * r , const uint32_t * mat , const uint8_t * vec , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) {
		r[i] = vec_dot32( mat , vec , len );
		mat += len;
	}
}


/* ======================= */


void vec_setzero( uint8_t * vec , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) vec[i]=0;
}

static inline void vec_mul( uint8_t * vec , unsigned c , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) vec[i] = full_mod31_16( c*((unsigned)vec[i]) );
}

static inline void vec_mad( uint8_t * accu_r , const uint8_t * vec , unsigned c , unsigned len )
{
	unsigned i,t;
	for(i=0;i<len;i++) {
		t = c*((unsigned)vec[i]);
		t += accu_r[i];
		accu_r[i] = remove_31( full_mod31_16(t) );
	}
}


void mat_rand( uint8_t * mat , uint8_t * invmat , unsigned len , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	unsigned i,j;
	uint8_t tmat[80*80*2];
	uint8_t tmp_swap[80*2];
	uint8_t *ptr;
	uint8_t *tptr;
	uint8_t tmp;

	vec_rand( mat , len*len , f_rng , p_rng );
	vec_fullreduce( mat , len*len ); /* 0 - 30 */

	ptr = tmat;
	for(i=0;i<len;i++) {
		vec_assign(ptr,&mat[i*len],len);
		ptr += len;
		vec_setzero(ptr,len);
		ptr[i] = 1;
		ptr += len;
	}

	for(i=0,ptr=tmat;i<len;i++,ptr+=2*len) {
		unsigned pivot = ptr[i];
		if( 0 == pivot ) {
			tptr = ptr + 2*len;
			for(j=i+1;j<len;j++) {
				if(0!=tptr[i]) {
					pivot = tptr[i];
					vec_assign(tmp_swap,ptr,2*len);
					vec_assign(ptr,tptr,2*len);
					vec_assign(tptr,tmp_swap,2*len);
					break;
				}
				tptr += 2*len;
			}
		}
		if( 0 == pivot ) return mat_rand( mat , invmat , len , f_rng , p_rng );
		pivot = inv_31( pivot );
		vec_mul(ptr,pivot,2*len);
		for(j=0,tptr=tmat;j<len;j++,tptr+=2*len) {
			if( i==j) continue;
			tmp=negative_31(tptr[i]);
			vec_mad(tptr,ptr,tmp,2*len);
		}
	}
	ptr = tmat;
	ptr += len;
	for(i=0;i<len;i++) {
		vec_assign(invmat,ptr,len);
		invmat += len;
		ptr += 2*len;
	}
}

inline static void vec_mul32_inp( uint32_t *vec , uint32_t c , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) vec[i] = vec[i]*c;
}

inline static void vec_fullreduce32_inp( uint32_t *vec , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) vec[i]=full_mod31_32(vec[i]);
}


int solve_linear( uint8_t * r , uint32_t * rowmat , const uint8_t * inp, const unsigned w )
{
	if(w>24)
		return -1;
	
	uint32_t cons[24];
	uint32_t swap[24];
	unsigned i,j;
	uint32_t pivot,tmp;
	vec_assign32( cons , inp , w );

	for(i=0;i<w;i++){
		pivot = rowmat[i*w+i] = remove_31( full_mod31_32(rowmat[i*w+i]) );
		if( 0 == pivot ) {
			for(j=i+1;j<w;j++){
				pivot = rowmat[j*w+i] = remove_31( full_mod31_32(rowmat[j*w+i]) );
				if( 0 == pivot ) continue;
				tmp = cons[i]; cons[i]=cons[j]; cons[j]=tmp;
				vec_assign((uint8_t*)swap,(uint8_t*)(&rowmat[i*w+i]),(w-i)*4);
				vec_assign((uint8_t*)(&rowmat[i*w+i]),(uint8_t*)(&rowmat[j*w+i]),(w-i)*4);
				vec_assign((uint8_t*)(&rowmat[j*w+i]),(uint8_t*)swap,(w-i)*4);
				break;
			}
		}
		pivot = inv_31( pivot );
		if( 0 == pivot ) return -1;
		if(w>(i+1)) {
			vec_mul32_inp(&rowmat[i*w+i+1],pivot,w-(i+1));
			vec_fullreduce32_inp(&rowmat[i*w+i+1],w-(i+1));
		}
		cons[i] = full_mod31_32( cons[i]*pivot );

		for(j=i+1;j<w;j++){
			tmp = remove_31( full_mod31_32(rowmat[j*w+i]) );
			if(0==tmp) continue;
			tmp=negative_31(tmp);
			vec_mad3232( &rowmat[j*w+i+1] , &rowmat[i*w+i+1] , tmp , w-(i+1) );
			cons[j] += cons[i]*tmp;
		}
	}

	r[w-1] = cons[w-1];
	for(i=w-1;i>0;i--){
		unsigned t = i-1;
		r[t] = cons[t] + negative_31( vec_dot32( &rowmat[t*w+i] , &r[i] , w-i ) );
	}
	return 0;
}


/* ======================== */


#define EVAL(w,h) \
	uint32_t tmp[w]; \
	uint32_t accu_r[h] = {0}; \
	unsigned i,j; \
	const uint8_t * ptr = &poly->q[0][0]; \
	for(i=0;i<w;i++){ vec_mad32(accu_r,poly->l[i],inp[i],h); } \
	for(i=0;i<w;i++){ \
		vec_mul32( tmp , &inp[i] , inp[i] , w-i ); \
		for(j=0;j<w-i;j++) { \
			vec_mad32(accu_r,ptr,tmp[j],h); \
			ptr += h; \
		} \
	} \
	vec_fullreduce32_cvt( r , accu_r , h ); \
	vec_fullreduce( r , h );


void eval_q64x40( uint8_t *r , const qpoly_64x40_t *poly , const uint8_t * inp )
{
	EVAL( 64 , 40 );
}

void eval_q24x20( uint8_t *r , const qpoly_24x20_t *poly , const uint8_t * inp )
{
	EVAL( 24 , 20 );
}

void eval_q44x20( uint8_t *r , const qpoly_44x20_t *poly , const uint8_t * inp )
{
	EVAL( 44 , 20 );
}

void eval_q80x52( uint8_t *r , const qpoly_80x52_t *poly , const uint8_t * inp )
{
	EVAL( 80 , 52 );
}

void eval_q26x24( uint8_t *r , const qpoly_26x24_t *poly , const uint8_t * inp )
{
	EVAL( 26 , 24 );
}

void eval_q52x4( uint8_t *r , const qpoly_52x4_t *poly , const uint8_t * inp )
{
	EVAL( 52 , 4 );
}


void eval_q56x24( uint8_t *r , const qpoly_56x24_t *poly , const uint8_t * inp )
{
	EVAL( 56 , 24 );
}






static inline void vec_mul8(uint8_t * r, const uint8_t * vec , unsigned c , unsigned len )
{
	unsigned i,t;
	for(i=0;i<len;i++){
		t = c * ((unsigned)vec[i]);
		r[i] = full_mod31_16(t);
	}
}


#define IDX(idx,n_var) (n_var+n_var-idx+1)*(idx)/2


void interpolate_64x40( qpoly_64x40_t * poly , void (*q_poly)(uint8_t *r,const void*,const uint8_t*), const void *key )
{
	static const unsigned n = 64;
	static const unsigned m = 40;
	uint8_t t[n];
	uint8_t rn1[m];
	unsigned i,j;

	vec_setzero(t,n);
	for(i=0;i<n;i++){
		t[i]=1;
		q_poly(poly->l[i],key,t);
		t[i]=negative_31(1);
		q_poly(rn1,key,t);
		t[i]=0;

		vec_add(rn1,poly->l[i],m);
		vec_mul8(poly->q[IDX(i,n)],rn1,16,m); /* 16 = 1/2 */

		vec_negative(rn1,poly->q[IDX(i,n)],m);
		vec_add(poly->l[i],rn1,m);
		vec_fullreduce(poly->l[i],m);
		vec_fullreduce(poly->q[IDX(i,n)],m);
	}

	for(i=0;i<n;i++){
		unsigned base = IDX(i,n);
		for(j=i+1;j<n;j++) {
			t[i]=1;
			t[j]=1;
			q_poly(poly->q[base+j-i],key,t);
			t[i]=0;
			t[j]=0;

			vec_negative(rn1,poly->l[i],m);
			vec_add(poly->q[base+j-i],rn1,m);
			vec_fullreduce(poly->q[base+j-i],m);

			vec_negative(rn1,poly->l[j],m);
			vec_add(poly->q[base+j-i],rn1,m);
			vec_fullreduce(poly->q[base+j-i],m);

			vec_negative(rn1,poly->q[base],m);
			vec_add(poly->q[base+j-i],rn1,m);
			vec_fullreduce(poly->q[base+j-i],m);

			vec_negative(rn1,poly->q[IDX(j,n)],m);
			vec_add(poly->q[base+j-i],rn1,m);
			vec_fullreduce(poly->q[base+j-i],m);
		}
	}
}


void interpolate_80x52( qpoly_80x52_t * poly , void (*q_poly)(uint8_t *r,const void*,const uint8_t*), const void *key )
{
	/* a copy of interpolate_64x40 */
	static const unsigned n = 80;
	static const unsigned m = 52;
	uint8_t t[n];
	uint8_t rn1[m];
	unsigned i,j;

	vec_setzero(t,n);
	for(i=0;i<n;i++){
		t[i]=1;
		q_poly(poly->l[i],key,t);
		t[i]=negative_31(1);
		q_poly(rn1,key,t);
		t[i]=0;

		vec_add(rn1,poly->l[i],m);
		vec_mul8(poly->q[IDX(i,n)],rn1,16,m); /* 16 = 1/2 */

		vec_negative(rn1,poly->q[IDX(i,n)],m);
		vec_add(poly->l[i],rn1,m);
		vec_fullreduce(poly->l[i],m);
		vec_fullreduce(poly->q[IDX(i,n)],m);
	}

	for(i=0;i<n;i++){
		unsigned base = IDX(i,n);
		for(j=i+1;j<n;j++) {
			t[i]=1;
			t[j]=1;
			q_poly(poly->q[base+j-i],key,t);
			t[i]=0;
			t[j]=0;

			vec_negative(rn1,poly->l[i],m);
			vec_add(poly->q[base+j-i],rn1,m);
			vec_fullreduce(poly->q[base+j-i],m);

			vec_negative(rn1,poly->l[j],m);
			vec_add(poly->q[base+j-i],rn1,m);
			vec_fullreduce(poly->q[base+j-i],m);

			vec_negative(rn1,poly->q[base],m);
			vec_add(poly->q[base+j-i],rn1,m);
			vec_fullreduce(poly->q[base+j-i],m);

			vec_negative(rn1,poly->q[IDX(j,n)],m);
			vec_add(poly->q[base+j-i],rn1,m);
			vec_fullreduce(poly->q[base+j-i],m);
		}
	}
}

