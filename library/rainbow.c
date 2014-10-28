#define __POLARSSL__

#if defined(__POLARSSL__)
#include "rainbow_tts/run_config.h"
#include "rainbow_tts/rainbow.h"
#include "rainbow_tts/linear31.h"
#include "rainbow_tts/_hash_sha256.h"
#else
#include "run_config.h"
#include "rainbow.h"
#include "linear31.h"
#include "_hash_sha256.h"
#endif




#if defined(__RAINBOW__)||defined(__TTS__)

#if 0
static inline int verify( const uint8_t * md , const qpoly_64x40_t * key , const uint8_t * s )
{
	uint8_t r[40];
	eval_q64x40( r , key , s );
	return vec_cmp40(md,r);
}
#endif



static void pack_qpoly_64x40( uint8_t *pubkey , const uint8_t * qp )
{
	unsigned i;
	for(i=0;i<sizeof(qpoly_64x40_t)/8;i++){
		pack_40b_31x8( pubkey , qp );
		pubkey += 5;
		qp += 8;
	}
}

inline static void vec_mad32( uint32_t * accu_r , const uint8_t * vec , unsigned c , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) accu_r[i] += c*((unsigned)vec[i]);
}
inline static void vec_mul32( uint32_t * r , const uint8_t * vec , unsigned c , unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) r[i] = c*((unsigned)vec[i]);
}


int tts_verify( const uint8_t * md192b , const uint8_t * key , const uint8_t * s320b )
{
	uint8_t s[64];
	uint32_t accu_r[40] = {0};
	uint32_t tmp[64];
	unsigned i,j;
	uint8_t partial_key[40];

	unpack_31x8_40b( s , s320b );
	unpack_31x8_40b( &s[8] , &s320b[5] );
	unpack_31x8_40b( &s[16] , &s320b[10] );
	unpack_31x8_40b( &s[24] , &s320b[15] );
	unpack_31x8_40b( &s[32] , &s320b[20] );
	unpack_31x8_40b( &s[40] , &s320b[25] );
	unpack_31x8_40b( &s[48] , &s320b[30] );
	unpack_31x8_40b( &s[56] , &s320b[35] );

        for(i=0;i<64;i++){
		unpack_31x8_40b(&partial_key[0],&key[0]);
		unpack_31x8_40b(&partial_key[8],&key[5]);
		unpack_31x8_40b(&partial_key[16],&key[10]);
		unpack_31x8_40b(&partial_key[24],&key[15]);
		unpack_31x8_40b(&partial_key[32],&key[20]);
		key += 25;
		vec_mad32(accu_r,partial_key,s[i],40);
	}
        for(i=0;i<64;i++){
		vec_mul32( tmp , &s[i] , s[i] , 64-i );
		for(j=0;j<64-i;j++) {
			unpack_31x8_40b(&partial_key[0],&key[0]);
			unpack_31x8_40b(&partial_key[8],&key[5]);
			unpack_31x8_40b(&partial_key[16],&key[10]);
			unpack_31x8_40b(&partial_key[24],&key[15]);
			unpack_31x8_40b(&partial_key[32],&key[20]);
			key += 25;
			vec_mad32(accu_r,partial_key,tmp[j],40);
		}
	}
	vec_fullreduce32_cvt( s , accu_r , 40 );
	vec_fullreduce( s , 40 );

	cvt_bin96_31x20( (uint32_t *) &partial_key[0] , s );
	cvt_bin96_31x20( (uint32_t *) &partial_key[12] , &s[20] );

	j = 0;
	for( i=0;i<6;i++) j |= ((uint32_t*)partial_key)[i]^((const uint32_t *)md192b)[i];

	return (0==j)?0:-1;
}

#endif /* defined(__RAINBOW__)||defined(__TTS__)  */





#if defined(__TTS__)||defined(__TTS_2__)
static void vec_shuffle( uint8_t * vec , unsigned len , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	unsigned i;
	unsigned idx;
	uint8_t tmp;
	uint8_t tmp64[64];
	f_rng(p_rng,tmp64,64);
	for(i=0;i<len;i++) {
		idx = tmp64[i]%len;
		tmp = vec[i];
		vec[i]=vec[idx];
		vec[idx]=tmp;
	}
	f_rng(p_rng,tmp64,64);
	for(i=0;i<len;i++) {
		idx = tmp64[i]%len;
		tmp = vec[i];
		vec[i]=vec[idx];
		vec[idx]=tmp;
	}
	f_rng(p_rng,tmp64,64);
	for(i=0;i<len;i++) {
		idx = tmp64[i]%len;
		tmp = vec[i];
		vec[i]=vec[idx];
		vec[idx]=tmp;
	}
}

static inline void vec_choose( uint8_t *r , const uint8_t *idx, const uint8_t *vec, unsigned len )
{
	unsigned i;
	for(i=0;i<len;i++) r[i]=vec[idx[i]];
}

#endif /* defined(__TTS__)||defined(__TTS_2__) */

#if defined(__TTS__)

static void gen_ov_rowmat1( uint32_t r_rowmat[20][20] , const tts_seckey_t * key , const uint8_t * v_vec )
{
	unsigned i,j;
	uint8_t picked[20];
	for(i=0;i<20;i++){
		vec_choose(picked,key->l1_pi[i],v_vec,20);
		for(j=0;j<20;j++) r_rowmat[i][j]=((uint32_t)picked[j])*((uint32_t)key->l1_coefpi[i][j]);
		r_rowmat[i][i] += 1;
	}
}
static void calc_constant1( uint8_t * r , const tts_seckey_t * key , const uint8_t * vec )
{
	unsigned i;
	uint8_t picked[24];
	uint32_t r32[20];
	for(i=0;i<20;i++){
		vec_choose(picked,&key->l1_pi[i][20],vec,4);
		r32[i] = ((uint32_t)key->l1_coefpi[i][20])*((uint32_t)picked[0])*((uint32_t)picked[1])+
			((uint32_t)key->l1_coefpi[i][21])*((uint32_t)picked[2])*((uint32_t)picked[3]);
	}
	vec_choose(picked,key->l1_sigma,vec,24);
	for(i=0;i<20;i++)
		r32[i]+=((uint32_t)picked[i])*((uint32_t)key->l1_coefsigma[i]);
	r32[0] += ((uint32_t)picked[20])*((uint32_t)key->l1_coefsigma[20]);
	r32[1] += ((uint32_t)picked[21])*((uint32_t)key->l1_coefsigma[21]);
	r32[2] += ((uint32_t)picked[22])*((uint32_t)key->l1_coefsigma[22]);
	r32[3] += ((uint32_t)picked[23])*((uint32_t)key->l1_coefsigma[23]);
	vec_fullreduce32_cvt(r,r32,20);
}
static void gen_ov_rowmat2( uint32_t r_rowmat[20][20] , const tts_seckey_t * key , const uint8_t * v_vec )
{
	unsigned i,j;
	uint8_t picked[40];
	for(i=0;i<20;i++){
		vec_choose(picked,key->l2_pi[i],v_vec,40);
		for(j=0;j<20;j++) r_rowmat[i][j]=((uint32_t)picked[j*2])*((uint32_t)key->l2_coefpi[i][j*2])
			+((uint32_t)picked[j*2+1])*((uint32_t)key->l2_coefpi[i][j*2+1]);
		r_rowmat[i][i] += 1;
	}
}
static void calc_constant2( uint8_t * r , const tts_seckey_t * key , const uint8_t * vec )
{
	unsigned i;
	uint8_t picked[44];
	uint32_t r32[20];
	for(i=0;i<20;i++){
		vec_choose(picked,&key->l2_pi[i][40],vec,4);
		r32[i] = ((uint32_t)key->l2_coefpi[i][40])*((uint32_t)picked[0])*((uint32_t)picked[1])+
			((uint32_t)key->l2_coefpi[i][41])*((uint32_t)picked[2])*((uint32_t)picked[3]);
	}
	vec_choose(picked,key->l2_sigma,vec,44);
	for(i=0;i<20;i++)
		r32[i] += ((uint32_t)picked[i*2])*((uint32_t)key->l2_coefsigma[i*2])
			+ ((uint32_t)picked[i*2+1])*((uint32_t)key->l2_coefsigma[i*2+1]);
	r32[0] += ((uint32_t)picked[40])*((uint32_t)key->l2_coefsigma[40]);
	r32[1] += ((uint32_t)picked[41])*((uint32_t)key->l2_coefsigma[41]);
	r32[2] += ((uint32_t)picked[42])*((uint32_t)key->l2_coefsigma[42]);
	r32[3] += ((uint32_t)picked[43])*((uint32_t)key->l2_coefsigma[43]);
	vec_fullreduce32_cvt(r,r32,20);
}




static void tts_sec_pubmap( uint8_t *r , const void *_key , const uint8_t * inp )
{
	const tts_seckey_t * key = (const tts_seckey_t *)_key;
	uint32_t r32[64] = {0};
	uint8_t tmp[64] = {0};
	uint8_t tmp2[40] = {0};
	uint8_t tmp3[20] = {0};

	uint32_t rowmat[20][20];

	vec_assign32( r32 , key->sc , 64 );
	mat_mad32( r32 , &key->s[0][0] , inp , 64 );
	vec_fullreduce32_cvt( tmp , r32 , 64 );

/* __TTS__ */
	gen_ov_rowmat1( rowmat , key , tmp );
	calc_constant1(tmp2, key , tmp );
	rowmat_mul32( tmp3 , &rowmat[0][0] , tmp+24 , 20 );
	vec_add( tmp2 , tmp3 , 20 );

	gen_ov_rowmat2( rowmat , key , tmp );
	calc_constant2( &tmp2[20] , key , tmp );
	rowmat_mul32( tmp3 , &rowmat[0][0] , tmp+44 , 20 );
	vec_add( &tmp2[20] , tmp3 , 20 );
/* __TTS__ */

	vec_assign32( r32 , key->tc , 40 );
	mat_mad32( r32 , &key->t[0][0] , tmp2 , 40 );
	vec_fullreduce32_cvt( r , r32 , 40 );
	vec_fullreduce( r , 40 ); /* remove 31 */
}


static int do_tts_genkey( uint8_t * pubkey , uint8_t * seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	qpoly_64x40_t * pk = (qpoly_64x40_t*) pubkey;
	tts_seckey_t * sk = (tts_seckey_t*) seckey;
	uint8_t inv_s[64*64];
	uint8_t inv_t[40*40];
	uint8_t inp64[64]={0};
	uint8_t out40[40]={0};

/* __TTS__ */
	unsigned i;
	uint8_t idx[44];
	f_rng(p_rng,sk->extra_random,32);
	vec_rand( sk->l1_coefsigma , 24 , f_rng , p_rng );
	vec_rand( sk->l2_coefsigma , 44 , f_rng , p_rng );
	for(i=0;i<44;i++) idx[i]=i;
	vec_shuffle(idx,24, f_rng , p_rng );
	vec_assign( sk->l1_sigma , idx , 24 );
	for(i=0;i<20;i++) {
		vec_shuffle(idx,24, f_rng , p_rng );
		vec_assign( sk->l1_pi[i] , idx , 24 );
		vec_rand( sk->l1_coefpi[i] , 22 , f_rng , p_rng );
	}
	vec_shuffle(idx,44, f_rng , p_rng );
	vec_assign( sk->l2_sigma , idx , 44 );
	for(i=0;i<20;i++) {
		vec_shuffle(idx,44, f_rng , p_rng );
		vec_assign( sk->l2_pi[i] , idx , 44 );
		vec_rand( sk->l2_coefpi[i] , 42 , f_rng , p_rng );
	}
/* __TTS__ */

	vec_rand( sk->sc , 64 , f_rng , p_rng );
	vec_setzero( sk->tc , 40 );

	mat_rand( sk->s[0] , inv_s , 64 , f_rng , p_rng );
	mat_rand( sk->t[0] , inv_t , 40 , f_rng , p_rng );

/* __TTS__ */
	tts_sec_pubmap( out40 , sk , inp64 );
	vec_negative( sk->tc , out40 , 40 );
	interpolate_64x40( pk , tts_sec_pubmap , (void *)sk );
/* __TTS__ */

	vec_assign( sk->s[0] , inv_s , 64*64 );
	vec_assign( sk->t[0] , inv_t , 40*40 );

	vec_negative( sk->sc , sk->sc , 64 );
	vec_negative( sk->tc , sk->tc , 40 );

	return 0;
}

static int do_tts_sign( uint8_t * s , const tts_seckey_t * key , const uint8_t * m )
{
	uint32_t r32[64] = {0};
	uint8_t tmp[64];
	uint8_t tmp2[40];
	uint8_t tmp3[20];
	unsigned i;
	int badluck;
	union{
	uint8_t v8[64];
	uint32_t v32[16];
	}hash;
	uint32_t rowmat[20][20];

	vec_assign( tmp2 , m , 40 );
	vec_add( tmp2 , key->tc , 40 );
	mat_mad32( r32 , &key->t[0][0] , tmp2 , 40 );
	vec_fullreduce32_cvt( tmp2 , r32 , 40 );

/* __TTS__ */
	/* sanity check of key */
	for(i=0;i<24;i++) if(key->l1_sigma[i]>24) return -100;
	for(i=0;i<44;i++) if(key->l2_sigma[i]>44) return -100;
	for(i=0;i<20;i++){
		unsigned j;
		for(j=0;j<24;j++) if(key->l1_pi[i][j]>24) return -100;
		for(j=0;j<44;j++) if(key->l2_pi[i][j]>44) return -100;
	}

	_hash_sha256(hash.v8,(const uint8_t *)key,sizeof(*key));
	for(i=0;i<24;i++) hash.v8[32+i]=m[i];
	_hash_sha256(hash.v8,hash.v8,56);
	for(i=0;i<5;i++) {
		if(0!=i) _hash_sha256(hash.v8,hash.v8,32);
		cvt_31x4_bin24(tmp,hash.v32[0]);
		cvt_31x4_bin24(tmp+4,hash.v32[1]);
		cvt_31x4_bin24(tmp+8,hash.v32[2]);
		cvt_31x4_bin24(tmp+12,hash.v32[3]);
		cvt_31x4_bin24(tmp+16,hash.v32[4]);
		cvt_31x4_bin24(tmp+20,hash.v32[5]);

		calc_constant1( tmp3 , key , tmp );
		vec_negative( tmp3 , tmp3 , 20 );
		vec_add( tmp3 , tmp2 , 20 );
		gen_ov_rowmat1( rowmat , key , tmp );
		badluck = solve_linear( &tmp[24] , &rowmat[0][0] , tmp3, 20 );
		if( 0 != badluck ) continue;

		calc_constant2( tmp3 , key , tmp );
		vec_negative( tmp3 , tmp3 , 20 );
		vec_add( tmp3 , &tmp2[20] , 20 );
		gen_ov_rowmat2( rowmat , key , tmp );
/* __TTS__ */
		badluck = solve_linear( &tmp[44] , &rowmat[0][0] , tmp3, 20 );
		if( 0 == badluck ) break;
	}
	if( 0 != badluck ) return -1;

	vec_add(tmp, key->sc , 64 );
	vec_setzero((uint8_t *)r32,64*4);
	mat_mad32( r32 , &key->s[0][0] , tmp , 64 );
	vec_fullreduce32_cvt( s , r32 , 64 );

	vec_fullreduce( s , 64 ); /* remove 31 */
	return 0;
}







#endif /* defined(__TTS__) */




#if defined(__RAINBOW__)

static void gen_ov_rowmat( uint32_t r_rowmat[20][20] , const uint8_t ol_rowmat[20][20] , const uint8_t * ov_rowmat 
	, const uint8_t * v_vec , unsigned v_len )
{
	unsigned i,j;
	for(i=0;i<20;i++){
		for(j=0;j<20;j++) {
			r_rowmat[i][j] = ol_rowmat[i][j];
			r_rowmat[i][j] += (uint32_t)vec_dot( ov_rowmat , v_vec , v_len );
			ov_rowmat += v_len;
		}
	}
}


static void rb_sec_pubmap( uint8_t *r , const void *_key , const uint8_t * inp )
{
	const rb_seckey_t * key = (const rb_seckey_t *)_key;
	uint32_t r32[64] = {0};
	uint8_t tmp[64] = {0};
	uint8_t tmp2[40] = {0};
	uint8_t tmp3[20] = {0};

	uint32_t rowmat[20][20];

	vec_assign32( r32 , key->sc , 64 );
	mat_mad32( r32 , &key->s[0][0] , inp , 64 );
	vec_fullreduce32_cvt( tmp , r32 , 64 );

/* __RAINBOW__ */
	gen_ov_rowmat( rowmat , key->ol1st_rowmat , & key->ov1st_rowmat[0][0][0] , tmp , 24 );
	rowmat_mul32( tmp3 , &rowmat[0][0] , tmp+24 , 20 );
	eval_q24x20( tmp2 , &(key->vv1st) , tmp );
	vec_add( tmp2 , tmp3 , 20 );

	gen_ov_rowmat( rowmat , key->ol2nd_rowmat , & key->ov2nd_rowmat[0][0][0] , tmp , 44 );
	rowmat_mul32( tmp3 , &rowmat[0][0] , tmp+44 , 20 );
	eval_q44x20( &tmp2[20] , &(key->vv2nd) , tmp );
	vec_add( &tmp2[20] , tmp3 , 20 );
/* __RAINBOW__ */

	vec_assign32( r32 , key->tc , 40 );
	mat_mad32( r32 , &key->t[0][0] , tmp2 , 40 );
	vec_fullreduce32_cvt( r , r32 , 40 );
	vec_fullreduce( r , 40 ); /* remove 31 */
}


static int do_rb_genkey( uint8_t * pubkey , uint8_t * seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	qpoly_64x40_t * pk = (qpoly_64x40_t*) pubkey;
	rb_seckey_t * sk = (rb_seckey_t*) seckey;
	uint8_t inv_s[64*64];
	uint8_t inv_t[40*40];
	uint8_t inp64[64]={0};
	uint8_t out40[40]={0};

/* __RAINBOW__ */
	vec_rand( (uint8_t *)&sk->vv1st , sizeof(qpoly_24x20_t) , f_rng , p_rng );
	vec_rand( &sk->ov1st_rowmat[0][0][0] , 20*20*24 , f_rng , p_rng );
	vec_rand( &sk->ol1st_rowmat[0][0] , 20*20 , f_rng , p_rng );
	vec_rand( (uint8_t *)&sk->vv2nd , sizeof(qpoly_44x20_t) , f_rng , p_rng );
	vec_rand( &sk->ov2nd_rowmat[0][0][0] , 20*20*44 , f_rng , p_rng );
	vec_rand( &sk->ol2nd_rowmat[0][0] , 20*20 , f_rng , p_rng );
/* __RAINBOW__ */
	vec_rand( sk->sc , 64 , f_rng , p_rng );
	vec_setzero( sk->tc , 40 );

	mat_rand( sk->s[0] , inv_s , 64 , f_rng , p_rng );
	mat_rand( sk->t[0] , inv_t , 40 , f_rng , p_rng );

/* __RAINBOW__ */
	rb_sec_pubmap( out40 , sk , inp64 );
	vec_negative( sk->tc , out40 , 40 );
	interpolate_64x40( pk , rb_sec_pubmap , (void *)sk );
/* __RAINBOW__ */

	vec_assign( sk->s[0] , inv_s , 64*64 );
	vec_assign( sk->t[0] , inv_t , 40*40 );

	vec_negative( sk->sc , sk->sc , 64 );
	vec_negative( sk->tc , sk->tc , 40 );

	return 0;
}



static int do_rb_sign( uint8_t * s , const rb_seckey_t * key , const uint8_t * m )
{
	uint32_t r32[64] = {0};
	uint8_t tmp[64];
	uint8_t tmp2[40];
	uint8_t tmp3[20];
	unsigned i;
	int badluck;
	union{
	uint8_t v8[64];
	uint32_t v32[16];
	}hash;
	uint32_t rowmat[20][20];

	vec_assign( tmp2 , m , 40 );
	vec_add( tmp2 , key->tc , 40 );
	mat_mad32( r32 , &key->t[0][0] , tmp2 , 40 );
	vec_fullreduce32_cvt( tmp2 , r32 , 40 );

	_hash_sha256(hash.v8,(const uint8_t *)key,sizeof(*key));
	for(i=0;i<24;i++) hash.v8[32+i]=m[i];
	_hash_sha256(hash.v8,hash.v8,56);
	for(i=0;i<5;i++) {
		if(0!=i) _hash_sha256(hash.v8,hash.v8,32);
		cvt_31x4_bin24(tmp,hash.v32[0]);
		cvt_31x4_bin24(tmp+4,hash.v32[1]);
		cvt_31x4_bin24(tmp+8,hash.v32[2]);
		cvt_31x4_bin24(tmp+12,hash.v32[3]);
		cvt_31x4_bin24(tmp+16,hash.v32[4]);
		cvt_31x4_bin24(tmp+20,hash.v32[5]);

/* __RAINBOW__ */
		eval_q24x20( tmp3 , &(key->vv1st) , tmp );
		vec_negative( tmp3 , tmp3 , 20 );
		vec_add( tmp3 , tmp2 , 20 );
		gen_ov_rowmat( rowmat , key->ol1st_rowmat , & key->ov1st_rowmat[0][0][0] , tmp , 24 );
		badluck = solve_linear( &tmp[24] , &rowmat[0][0] , tmp3, 20 );
		if( 0 != badluck ) continue;

		eval_q44x20( tmp3 , &(key->vv2nd) , tmp );
		vec_negative( tmp3 , tmp3 , 20 );
		vec_add( tmp3 , &tmp2[20] , 20 );
		gen_ov_rowmat( rowmat , key->ol2nd_rowmat , & key->ov2nd_rowmat[0][0][0] , tmp , 44 );
/* __RAINBOW__ */
		badluck = solve_linear( &tmp[44] , &rowmat[0][0] , tmp3, 20 );
		if( 0 == badluck ) break;
	}
	if( 0 != badluck ) return -1;

	vec_add(tmp, key->sc , 64 );
	vec_setzero((uint8_t *)r32,64*4);
	mat_mad32( r32 , &key->s[0][0] , tmp , 64 );
	vec_fullreduce32_cvt( s , r32 , 64 );

	vec_fullreduce( s , 64 ); /* remove 31 */
	return 0;
}



#endif /* defined(__RAINBOW__) */





/*  binary interface  */


#if defined(__TTS__)

int tts_genkey( uint8_t * pubkey , uint8_t *seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	int r;
	qpoly_64x40_t pk;
	r = do_tts_genkey( (uint8_t *)&pk , seckey , f_rng , p_rng );
	pack_qpoly_64x40(pubkey, (uint8_t*)&pk);
	return r;
}

int tts_sign( uint8_t * s320b , const uint8_t * key , const uint8_t * md192b )
{
	uint8_t md[40];
	uint8_t s[64];
	int r;

	cvt_31x20_bin96(&md[0],(const uint32_t *)&md192b[0]);
	cvt_31x20_bin96(&md[20],(const uint32_t *)&md192b[12]);

	r = do_tts_sign( s , (tts_seckey_t*)key , md );

	pack_40b_31x8( s320b , s );
	pack_40b_31x8( &s320b[5] , &s[8] );
	pack_40b_31x8( &s320b[10] , &s[16] );
	pack_40b_31x8( &s320b[15] , &s[24] );
	pack_40b_31x8( &s320b[20] , &s[32] );
	pack_40b_31x8( &s320b[25] , &s[40] );
	pack_40b_31x8( &s320b[30] , &s[48] );
	pack_40b_31x8( &s320b[35] , &s[56] );

	return r;
}

#endif /* defined(__TTS__) */



#if defined(__RAINBOW__)

int rb_genkey( uint8_t * pubkey , uint8_t *seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	int r;
	qpoly_64x40_t pk;
	r = do_rb_genkey( (uint8_t *)&pk , seckey , f_rng , p_rng );
	pack_qpoly_64x40(pubkey, (uint8_t*)&pk);
	return r;
}

int rb_sign( uint8_t * s320b , const uint8_t * key , const uint8_t * md192b )
{
	uint8_t md[40];
	uint8_t s[64];
	int r;

	cvt_31x20_bin96(&md[0],(const uint32_t *)&md192b[0]);
	cvt_31x20_bin96(&md[20],(const uint32_t *)&md192b[12]);

	r = do_rb_sign( s , (rb_seckey_t*)key , md );

	pack_40b_31x8( s320b , s );
	pack_40b_31x8( &s320b[5] , &s[8] );
	pack_40b_31x8( &s320b[10] , &s[16] );
	pack_40b_31x8( &s320b[15] , &s[24] );
	pack_40b_31x8( &s320b[20] , &s[32] );
	pack_40b_31x8( &s320b[25] , &s[40] );
	pack_40b_31x8( &s320b[30] , &s[48] );
	pack_40b_31x8( &s320b[35] , &s[56] );

	return r;
}

#endif /* defined(__RAINBOW__) */







/* =================================================================   */









#if defined(__RAINBOW_2__)||defined(__TTS_2__)


static void pack_qpoly_80x52( uint8_t *pk , const uint8_t * qp )
{
	unsigned i;
	for(i=0;i<sizeof(qpoly_80x52_t)/8;i++){
		pack_40b_31x8( pk , qp );
		pk += 5;
		qp += 8;
	}
}

static void unpack_qpoly_80x52( uint8_t * qp , const uint8_t *pk )
{
	unsigned i;
	for(i=0;i<sizeof(qpoly_80x52_t)/8;i++){
		unpack_31x8_40b(qp,pk);
		pk += 5;
		qp += 8;
	}
}

int rb2_verify( const uint8_t * md , const uint8_t * packed_pk , const uint8_t * sig )
{
	uint8_t s[80];
	uint8_t r[52];
	uint32_t cp32[8];
	const uint32_t * md32 = (const uint32_t *)md;
	qpoly_80x52_t pk;
	int i,j;

	unpack_31x8_40b(s,sig);
	unpack_31x8_40b(&s[8],&sig[5]);
	unpack_31x8_40b(&s[16],&sig[10]);
	unpack_31x8_40b(&s[24],&sig[15]);
	unpack_31x8_40b(&s[32],&sig[20]);
	unpack_31x8_40b(&s[40],&sig[25]);
	unpack_31x8_40b(&s[48],&sig[30]);
	unpack_31x8_40b(&s[56],&sig[35]);
	unpack_31x8_40b(&s[64],&sig[40]);
	unpack_31x8_40b(&s[72],&sig[45]);

	unpack_qpoly_80x52( (uint8_t*)&pk , packed_pk );
	eval_q80x52( r , &pk , s );

	cvt_bin64_31x13( &cp32[0] , &cp32[1] , &r[0] );
	cvt_bin64_31x13( &cp32[2] , &cp32[3] , &r[13] );
	cvt_bin64_31x13( &cp32[4] , &cp32[5] , &r[26] );
	cvt_bin64_31x13( &cp32[6] , &cp32[7] , &r[39] );

	j=0;
	for(i=0;i<8;i++) j |= (cp32[i]^md32[i]);
	return (j==0)?0:-1;
}


#endif /* defined(__RAINBOW_2__)||defined(__TTS_2__) */





#if defined(__RAINBOW_2__)

static void rb2_gen_ov_rowmat( uint32_t * r_rowmat , const uint8_t ol_rowmat[24][24] , const uint8_t * ov_rowmat 
	, const uint8_t * v_vec , unsigned v_len )
{
	const unsigned w=24;
	unsigned i,j;
	for(i=0;i<w;i++){
		for(j=0;j<w;j++) {
			r_rowmat[i*w+j] = ol_rowmat[i][j];
			r_rowmat[i*w+j] += (uint32_t)vec_dot( ov_rowmat , v_vec , v_len );
			ov_rowmat += v_len;
		}
	}
}

static void rb2_gen_ov_rowmat_4( uint32_t * r_rowmat , const uint8_t ol_rowmat[4][4] , const uint8_t * ov_rowmat 
	, const uint8_t * v_vec , unsigned v_len )
{
	const unsigned w=4;
	unsigned i,j;
	for(i=0;i<w;i++){
		for(j=0;j<w;j++) {
			r_rowmat[i*w+j] = ol_rowmat[i][j];
			r_rowmat[i*w+j] += (uint32_t)vec_dot( ov_rowmat , v_vec , v_len );
			ov_rowmat += v_len;
		}
	}
}

static void rb2_rand_cmap( rb2_seckey_t * sk , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	vec_rand( (uint8_t *)&sk->vv1st , sizeof(qpoly_26x24_t) , f_rng , p_rng );
	vec_rand( &sk->ov1st_rowmat[0][0][0] , 24*24*26 , f_rng , p_rng );
	vec_rand( &sk->ol1st_rowmat[0][0] , 24*24 , f_rng , p_rng );
	vec_rand( (uint8_t *)&sk->vv2nd , sizeof(qpoly_52x4_t) , f_rng , p_rng );
	vec_rand( &sk->ov2nd_rowmat[0][0][0] , 4*4*52 , f_rng , p_rng );
	vec_rand( &sk->ol2nd_rowmat[0][0] , 4*4 , f_rng , p_rng );
	vec_rand( (uint8_t *)&sk->vv3rd , sizeof(qpoly_56x24_t) , f_rng , p_rng );
	vec_rand( &sk->ov3rd_rowmat[0][0][0] , 24*24*56 , f_rng , p_rng );
	vec_rand( &sk->ol3rd_rowmat[0][0] , 24*24 , f_rng , p_rng );
}

static void rb2_cmap( uint8_t *r , const rb2_seckey_t *key , const uint8_t * inp )
{
	uint8_t tmp3[24];
	uint32_t rowmat[24*24];

	rb2_gen_ov_rowmat( rowmat , key->ol1st_rowmat , & key->ov1st_rowmat[0][0][0] , inp , 26 );
	rowmat_mul32( tmp3 , rowmat , inp+28 , 24 );
	eval_q26x24( r , &(key->vv1st) , inp );
	vec_add( r , tmp3 , 24 );

	rb2_gen_ov_rowmat_4( rowmat , key->ol2nd_rowmat , & key->ov2nd_rowmat[0][0][0] , inp , 52 );
	rowmat_mul32( tmp3 , rowmat , inp + 52 , 4 );
	eval_q52x4( r+24 , &(key->vv2nd) , inp );
	vec_add( r+24 , tmp3 , 4 );

	rb2_gen_ov_rowmat( rowmat , key->ol3rd_rowmat , & key->ov3rd_rowmat[0][0][0] , inp , 56 );
	rowmat_mul32( tmp3 , rowmat , inp+56 , 24 );
	eval_q56x24( r+28 , &(key->vv3rd) , inp );
	vec_add( r+28 , tmp3 , 24 );
}

static int rb2_invcmap( uint8_t * r , const rb2_seckey_t * key , const uint8_t * inp , uint32_t * hash )
{
	unsigned i;
	int badluck = 0;
	uint8_t tmp3[24];
	uint32_t rowmat[24*24];

	for(i=0;i<5;i++) {
		if(0 != i ) _hash_sha256((uint8_t *)hash,(uint8_t *)hash,32);

		cvt_31x6p5_bin32(r,hash[0]);
		cvt_31x6p5_bin32(r+6,hash[1]);
		cvt_31x6p5_bin32(r+12,hash[2]);
		cvt_31x6p5_bin32(r+18,hash[3]);
		cvt_31x6p5_bin32(r+24,hash[4]);

		eval_q26x24( tmp3 , &(key->vv1st) , r );
		vec_negative( tmp3 , tmp3 , 24 );
		vec_add( tmp3 , inp , 24 );
		rb2_gen_ov_rowmat( rowmat , key->ol1st_rowmat , & key->ov1st_rowmat[0][0][0] , r , 26 );
		badluck = solve_linear( r+28 , rowmat , tmp3, 24 );
		if( 0 != badluck ) continue;

		eval_q52x4( tmp3 , &(key->vv2nd) , r );
		vec_negative( tmp3 , tmp3 , 4 );
		vec_add( tmp3 , inp+24 , 4 );
		rb2_gen_ov_rowmat_4( rowmat , key->ol2nd_rowmat , & key->ov2nd_rowmat[0][0][0] , r , 52 );
		badluck = solve_linear( r+52 , rowmat , tmp3, 4 );
		if( 0 != badluck ) continue;

		eval_q56x24( tmp3 , &(key->vv3rd) , r );
		vec_negative( tmp3 , tmp3 , 24 );
		vec_add( tmp3 , inp+28 , 24 );
		rb2_gen_ov_rowmat( rowmat , key->ol3rd_rowmat , & key->ov3rd_rowmat[0][0][0] , r , 56 );

		badluck = solve_linear( r+56 , rowmat , tmp3, 24 );
		if( 0 == badluck ) return 0;
	}
	return -1;
}



/*  ---------------------------------------------------    */




static void rb2_sec_pubmap( uint8_t *r , const void *_key , const uint8_t * inp )
{
	const rb2_seckey_t * key = (const rb2_seckey_t *)_key;
	uint32_t r32[80];
	uint8_t tmp[80];
	uint8_t tmp2[52];

	vec_assign32( r32 , key->sc , 80 );
	mat_mad32( r32 , &key->s[0][0] , inp , 80 );
	vec_fullreduce32_cvt( tmp , r32 , 80 );

	rb2_cmap( tmp2 , key , tmp );

	vec_assign32( r32 , key->tc , 52 );
	mat_mad32( r32 , &key->t[0][0] , tmp2 , 52 );
	vec_fullreduce32_cvt( r , r32 , 52 );
	vec_fullreduce( r , 52 ); /* remove 31 */
}

static int do_rb2_genkey( uint8_t * pubkey , uint8_t * seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	qpoly_80x52_t * pk = (qpoly_80x52_t*) pubkey;
	rb2_seckey_t * sk = (rb2_seckey_t*) seckey;
	uint8_t inv_s[80*80];
	uint8_t inv_t[52*52];
	uint8_t inp64[80]={0};
	uint8_t out40[52]={0};

	vec_rand( sk->sc , 80 , f_rng , p_rng );
	vec_setzero( sk->tc , 52 );

	mat_rand( sk->s[0] , inv_s , 80 , f_rng , p_rng );
	mat_rand( sk->t[0] , inv_t , 52 , f_rng , p_rng );

/* __RAINBOW__ */
	rb2_rand_cmap( sk , f_rng , p_rng );
	rb2_sec_pubmap( out40 , sk , inp64 );
	vec_negative( sk->tc , out40 , 52 );
	interpolate_80x52( pk , rb2_sec_pubmap , (void *)sk );
/* __RAINBOW__ */

	vec_assign( sk->s[0] , inv_s , 80*80 );
	vec_assign( sk->t[0] , inv_t , 52*52 );

	vec_negative( sk->sc , sk->sc , 80 );
	vec_negative( sk->tc , sk->tc , 52 );

	return 0;
}



static int do_rb2_sign( uint8_t * s , const rb2_seckey_t * key , const uint8_t * m )
{
	uint32_t r32[80] = {0};
	uint8_t tmp[80];
	uint8_t tmp2[52];
	//uint8_t tmp3[24];
	int i;
	uint8_t hash[64];

	vec_assign( tmp2 , m , 52 );
	vec_add( tmp2 , key->tc , 52 );
	mat_mad32( r32 , &key->t[0][0] , tmp2 , 52 );
	vec_fullreduce32_cvt( tmp2 , r32 , 52 );

	_hash_sha256(hash,(const uint8_t *)key,sizeof(*key));
	for(i=0;i<32;i++) hash[32+i]=m[i];
	_hash_sha256(hash,hash,64);

	i = rb2_invcmap( tmp , key , tmp2 , (uint32_t *)hash );

	vec_add(tmp, key->sc , 80 );
	vec_setzero((uint8_t *)r32,80*4);
	mat_mad32( r32 , &key->s[0][0] , tmp , 80 );
	vec_fullreduce32_cvt( s , r32 , 80 );

	vec_fullreduce( s , 80 ); /* remove 31 */
	return 0;
}





int rb2_genkey( uint8_t * pubkey , uint8_t *seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	int r;
	qpoly_80x52_t pk;
	r = do_rb2_genkey( (uint8_t *)&pk , seckey , f_rng , p_rng );
	pack_qpoly_80x52(pubkey, (uint8_t*)&pk);
	return r;
	//return do_rb2_genkey(pubkey,seckey,f_rng,p_rng);
}

int rb2_sign( uint8_t * sig , const uint8_t * seckey , const uint8_t * _md )
{
	uint8_t md[52];
	uint8_t s[80];
	int r;
	const uint32_t *md32 = (const uint32_t *)_md;

	cvt_31x13_bin64( &md[0], md32[0] , md32[1] );
	cvt_31x13_bin64( &md[13], md32[2] , md32[3] );
	cvt_31x13_bin64( &md[26], md32[4] , md32[5] );
	cvt_31x13_bin64( &md[39], md32[6] , md32[7] );

	r = do_rb2_sign( s , (rb2_seckey_t*)seckey , md );

	pack_40b_31x8( sig , s );
	pack_40b_31x8( &sig[5] , &s[8] );
	pack_40b_31x8( &sig[10] , &s[16] );
	pack_40b_31x8( &sig[15] , &s[24] );
	pack_40b_31x8( &sig[20] , &s[32] );
	pack_40b_31x8( &sig[25] , &s[40] );
	pack_40b_31x8( &sig[30] , &s[48] );
	pack_40b_31x8( &sig[35] , &s[56] );
	pack_40b_31x8( &sig[40] , &s[64] );
	pack_40b_31x8( &sig[45] , &s[72] );

	return r;
}




#endif /* defined(__RAINBOW_2__) */






#if defined(__TTS_2__)


static void tts2_rand_cmap( tts2_seckey_t * sk , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
        unsigned i;
        uint8_t idx[56];
        f_rng(p_rng,sk->extra_random,32);
        vec_rand( sk->l1_coefsigma , 26 , f_rng , p_rng );
        vec_rand( sk->l2_coefsigma , 52 , f_rng , p_rng );
        vec_rand( sk->l3_coefsigma , 56 , f_rng , p_rng );
        for(i=0;i<56;i++) idx[i]=i;
        vec_shuffle(idx,26, f_rng , p_rng );
        vec_assign( sk->l1_sigma , idx , 26 );
        for(i=0;i<24;i++) {
                vec_shuffle(idx,26, f_rng , p_rng );
                vec_assign( sk->l1_pi[i] , idx , 26 );
		vec_rand( sk->l1_coefpi[i] , 25 , f_rng , p_rng );
        }
        vec_shuffle(idx,52, f_rng , p_rng );
        vec_assign( sk->l2_sigma , idx , 52 );
        for(i=0;i<4;i++) {
                vec_shuffle(idx,52, f_rng , p_rng );
                vec_assign( sk->l2_pi[i] , idx , 52 );
		vec_rand( sk->l2_coefpi[i] , 36 , f_rng , p_rng );
        }
        vec_shuffle(idx,56, f_rng , p_rng );
        vec_assign( sk->l3_sigma , idx , 56 );
        for(i=0;i<24;i++) {
                vec_shuffle(idx,56, f_rng , p_rng );
                vec_assign( sk->l3_pi[i] , idx , 56 );
		vec_rand( sk->l3_coefpi[i] , 52 , f_rng , p_rng );
        }
}
//        l1: v26, o24  linear: idx: 26 coef: 26   quad: 24x( idx:26 , coef: 25 (ov:24,vv:1) )
static void tts2_gen_ov_rowmat1( uint32_t *r_rowmat , const tts2_seckey_t * key , const uint8_t * vec )
{
	unsigned i,j;
	uint8_t picked[24];
	for(i=0;i<24;i++){
		vec_choose(picked,key->l1_pi[i],vec,24);
		for(j=0;j<24;j++) r_rowmat[i*24+j]=((uint32_t)picked[j])*((uint32_t)key->l1_coefpi[i][j]);
		r_rowmat[i*24+i] += 1;
	}
}
//        l2: v52, o4   linear: idx: 52 coef: 52   quad:  4x( idx:52 , coef: 36 (ov: 4x5=20, vv: 32/2=16) )
static void tts2_gen_ov_rowmat2( uint32_t *r_rowmat , const tts2_seckey_t * key , const uint8_t * vec )
{
	unsigned i,j;
	uint8_t picked[20];
	for(i=0;i<4;i++){
		vec_choose(picked,key->l2_pi[i],vec,20);
		for(j=0;j<4;j++) {
			r_rowmat[i*4+j]=((uint32_t)picked[j*5])*((uint32_t)key->l2_coefpi[i][j*5])
					+((uint32_t)picked[j*5+1])*((uint32_t)key->l2_coefpi[i][j*5+1])
					+((uint32_t)picked[j*5+2])*((uint32_t)key->l2_coefpi[i][j*5+2])
					+((uint32_t)picked[j*5+3])*((uint32_t)key->l2_coefpi[i][j*5+3])
					+((uint32_t)picked[j*5+4])*((uint32_t)key->l2_coefpi[i][j*5+4]);
		}
		r_rowmat[i*4+i] += 1;
	}
}
//        l3: v56, o24  linear: idx: 56 coef: 56   quad: 24x( idx:56 , coef: 52 (ov:24x2=48, vv: 8/2=4) )
static void tts2_gen_ov_rowmat3( uint32_t *r_rowmat , const tts2_seckey_t * key , const uint8_t * vec )
{
	unsigned i,j;
	uint8_t picked[48];
	for(i=0;i<24;i++){
		vec_choose(picked,key->l1_pi[i],vec,48);
		for(j=0;j<24;j++) r_rowmat[i*24+j]=((uint32_t)picked[j*2])*((uint32_t)key->l3_coefpi[i][j*2])
						+((uint32_t)picked[j*2+1])*((uint32_t)key->l3_coefpi[i][j*2+1]);
		r_rowmat[i*24+i] += 1;
	}
}
//        l1: v26, o24  linear: idx: 26 coef: 26   quad: 24x( idx:26 , coef: 25 (ov:24,vv:1) )
static void tts2_calc_constant1( uint8_t * r , const tts2_seckey_t * key , const uint8_t * vec )
{
	unsigned i;
	uint8_t picked[26];
	uint32_t r32[24];
	for(i=0;i<24;i++){
		vec_choose(picked,&key->l1_pi[i][24],vec,2);
		r32[i] = ((uint32_t)key->l1_coefpi[i][24])*((uint32_t)picked[0])*((uint32_t)picked[1]);
	}
	vec_choose(picked,key->l1_sigma,vec,26);
	for(i=0;i<24;i++)
		r32[i]+=((uint32_t)picked[i])*((uint32_t)key->l1_coefsigma[i]);
	r32[0] += ((uint32_t)picked[24])*((uint32_t)key->l1_coefsigma[24]);
	r32[1] += ((uint32_t)picked[25])*((uint32_t)key->l1_coefsigma[25]);
	vec_fullreduce32_cvt(r,r32,24);
}
//        l2: v52, o4   linear: idx: 52 coef: 52   quad:  4x( idx:52 , coef: 36 (ov: 4x5=20, vv: 32/2=16) )
static void tts2_calc_constant2( uint8_t * r , const tts2_seckey_t * key , const uint8_t * vec )
{
	unsigned i,j;
	uint8_t picked[52];
	uint32_t r32[4];
	for(i=0;i<4;i++){
		vec_choose(picked,&key->l2_pi[i][20],vec,32);
		r32[i] = 0;
		for(j=0;j<16;j++)
			r32[i] += ((uint32_t)key->l2_coefpi[i][20+j])*((uint32_t)picked[j*2])*((uint32_t)picked[j*2+1]);
	}
	vec_choose(picked,key->l2_sigma,vec,52);
	for(i=0;i<4;i++)
		for(j=0;j<13;j++)
			r32[i]+=((uint32_t)picked[i*13+j])*((uint32_t)key->l2_coefsigma[i*13+j]);
	vec_fullreduce32_cvt(r,r32,4);
}
//        l3: v56, o24  linear: idx: 56 coef: 56   quad: 24x( idx:56 , coef: 52 (ov:24x2=48, vv: 8/2=4) )
static void tts2_calc_constant3( uint8_t * r , const tts2_seckey_t * key , const uint8_t * vec )
{
	unsigned i;
	uint8_t picked[56];
	uint32_t r32[24];
	for(i=0;i<24;i++){
		vec_choose(picked,&key->l3_pi[i][48],vec,8);
		r32[i] = ((uint32_t)key->l3_coefpi[i][48])*((uint32_t)picked[0])*((uint32_t)picked[1])
			+((uint32_t)key->l3_coefpi[i][49])*((uint32_t)picked[2])*((uint32_t)picked[3])
			+((uint32_t)key->l3_coefpi[i][50])*((uint32_t)picked[4])*((uint32_t)picked[5])
			+((uint32_t)key->l3_coefpi[i][51])*((uint32_t)picked[6])*((uint32_t)picked[7]);
	}
	vec_choose(picked,key->l3_sigma,vec,56);
	for(i=0;i<24;i++)
		r32[i]+=((uint32_t)picked[i*2])*((uint32_t)key->l3_coefsigma[i*2])
			+((uint32_t)picked[i*2+1])*((uint32_t)key->l3_coefsigma[i*2+1]);
	for(i=0;i<8;i++)
		r32[i]+=((uint32_t)picked[48+i])*((uint32_t)key->l3_coefsigma[48+i]);
	vec_fullreduce32_cvt(r,r32,24);
}
static void tts2_cmap( uint8_t *r , const tts2_seckey_t *key , const uint8_t * inp )
{
	uint8_t tmp3[24];
	uint32_t rowmat[24*24];

	tts2_gen_ov_rowmat1( rowmat , key , inp );
	tts2_calc_constant1( r, key , inp );
	rowmat_mul32( tmp3 , rowmat , inp+28 , 24 );
	vec_add( r , tmp3 , 24 );

	tts2_gen_ov_rowmat2( rowmat , key , inp );
	tts2_calc_constant2( r + 24 , key , inp );
	rowmat_mul32( tmp3 , rowmat , inp+52 , 4 );
	vec_add( r + 24 , tmp3 , 4 );

	tts2_gen_ov_rowmat3( rowmat , key , inp );
	tts2_calc_constant3( r + 28 , key , inp );
	rowmat_mul32( tmp3 , rowmat , inp+56 , 24 );
	vec_add( r + 28 , tmp3 , 24 );
}

static int tts2_invcmap( uint8_t * r , const tts2_seckey_t * key , const uint8_t * inp , uint32_t * hash )
{
	unsigned i;
	int badluck = 0;
	uint8_t tmp3[24];
	uint32_t rowmat[24*24];

	/* sanity check of key */
	for(i=0;i<26;i++) if(key->l1_sigma[i]>26) return -100;
	for(i=0;i<52;i++) if(key->l2_sigma[i]>52) return -100;
	for(i=0;i<56;i++) if(key->l3_sigma[i]>56) return -100;
	for(i=0;i<24;i++){
		unsigned j;
		for(j=0;j<26;j++) if(key->l1_pi[i][j]>26) return -100;
		for(j=0;j<56;j++) if(key->l3_pi[i][j]>56) return -100;
	}
	for(i=0;i<4;i++){
		unsigned j;
		for(j=0;j<52;j++) if(key->l2_pi[i][j]>52) return -100;
	}

	for(i=0;i<5;i++) {
		if( 0 != i ) _hash_sha256((uint8_t *)hash,(uint8_t *)hash,32);

		cvt_31x6p5_bin32(r,hash[0]);
		cvt_31x6p5_bin32(r+6,hash[1]);
		cvt_31x6p5_bin32(r+12,hash[2]);
		cvt_31x6p5_bin32(r+18,hash[3]);
		cvt_31x6p5_bin32(r+24,hash[4]);

		tts2_calc_constant1( tmp3 , key , r );
		vec_negative( tmp3 , tmp3 , 24 );
		vec_add( tmp3 , inp , 24 );
		tts2_gen_ov_rowmat1( rowmat , key , r );
		badluck = solve_linear( r+28 , rowmat , tmp3, 24 );
		if( 0 != badluck ) continue;

		tts2_calc_constant2( tmp3 , key , r );
		vec_negative( tmp3 , tmp3 , 4 );
		vec_add( tmp3 , inp+24 , 4 );
		tts2_gen_ov_rowmat2( rowmat , key , r );
		badluck = solve_linear( r+52 , rowmat , tmp3, 4 );
		if( 0 != badluck ) continue;

		tts2_calc_constant3( tmp3 , key , r );
		vec_negative( tmp3 , tmp3 , 24 );
		vec_add( tmp3 , inp+28 , 24 );
		tts2_gen_ov_rowmat3( rowmat , key , r );

		badluck = solve_linear( r+56 , rowmat , tmp3, 24 );
		if( 0 == badluck ) return 0;
	}
	return -1;
}



/*  ---------------------------------------------------    */




static void tts2_sec_pubmap( uint8_t *r , const void *_key , const uint8_t * inp )
{
	const tts2_seckey_t * key = (const tts2_seckey_t *)_key;
	uint32_t r32[80];
	uint8_t tmp[80];
	uint8_t tmp2[52];

	vec_assign32( r32 , key->sc , 80 );
	mat_mad32( r32 , &key->s[0][0] , inp , 80 );
	vec_fullreduce32_cvt( tmp , r32 , 80 );

	tts2_cmap( tmp2 , key , tmp );

	vec_assign32( r32 , key->tc , 52 );
	mat_mad32( r32 , &key->t[0][0] , tmp2 , 52 );
	vec_fullreduce32_cvt( r , r32 , 52 );
	vec_fullreduce( r , 52 ); /* remove 31 */
}

static int do_tts2_genkey( uint8_t * pubkey , uint8_t * seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	qpoly_80x52_t * pk = (qpoly_80x52_t*) pubkey;
	tts2_seckey_t * sk = (tts2_seckey_t*) seckey;
	uint8_t inv_s[80*80];
	uint8_t inv_t[52*52];
	uint8_t inp64[80]={0};
	uint8_t out40[52]={0};

	vec_rand( sk->sc , 80 , f_rng , p_rng );
	vec_setzero( sk->tc , 52 );

	mat_rand( sk->s[0] , inv_s , 80 , f_rng , p_rng );
	mat_rand( sk->t[0] , inv_t , 52 , f_rng , p_rng );

/* __TTS__ */
	tts2_rand_cmap( sk , f_rng , p_rng );
	tts2_sec_pubmap( out40 , sk , inp64 );
	vec_negative( sk->tc , out40 , 52 );
	interpolate_80x52( pk , tts2_sec_pubmap , (void *)sk );
/* __TTS__ */

	vec_assign( sk->s[0] , inv_s , 80*80 );
	vec_assign( sk->t[0] , inv_t , 52*52 );

	vec_negative( sk->sc , sk->sc , 80 );
	vec_negative( sk->tc , sk->tc , 52 );

	return 0;
}



static int do_tts2_sign( uint8_t * s , const tts2_seckey_t * key , const uint8_t * m )
{
	uint32_t r32[80] = {0};
	uint8_t tmp[80];
	uint8_t tmp2[52];
	int i;
	uint8_t hash[64];

	vec_assign( tmp2 , m , 52 );
	vec_add( tmp2 , key->tc , 52 );
	mat_mad32( r32 , &key->t[0][0] , tmp2 , 52 );
	vec_fullreduce32_cvt( tmp2 , r32 , 52 );

	_hash_sha256(hash,(const uint8_t *)key,sizeof(*key));
	for(i=0;i<32;i++) hash[32+i]=m[i];
	_hash_sha256(hash,hash,64);

	i = tts2_invcmap( tmp , key , tmp2 , (uint32_t *)hash );
	if( 0 != i ) return -1;

	vec_add(tmp, key->sc , 80 );
	vec_setzero((uint8_t *)r32,80*4);
	mat_mad32( r32 , &key->s[0][0] , tmp , 80 );
	vec_fullreduce32_cvt( s , r32 , 80 );

	vec_fullreduce( s , 80 ); /* remove 31 */
	return 0;
}





int tts2_genkey( uint8_t * pubkey , uint8_t *seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
	int r;
	qpoly_80x52_t pk;
	r = do_tts2_genkey( (uint8_t *)&pk , seckey , f_rng , p_rng );
	pack_qpoly_80x52(pubkey, (uint8_t*)&pk);
	return r;
	//return do_rb2_genkey(pubkey,seckey,f_rng,p_rng);
}

int tts2_sign( uint8_t * sig , const uint8_t * seckey , const uint8_t * _md )
{
	uint8_t md[52];
	uint8_t s[80];
	int r;
	const uint32_t *md32 = (const uint32_t *)_md;

	cvt_31x13_bin64( &md[0], md32[0] , md32[1] );
	cvt_31x13_bin64( &md[13], md32[2] , md32[3] );
	cvt_31x13_bin64( &md[26], md32[4] , md32[5] );
	cvt_31x13_bin64( &md[39], md32[6] , md32[7] );

	r = do_tts2_sign( s , (tts2_seckey_t*)seckey , md );

	pack_40b_31x8( sig , s );
	pack_40b_31x8( &sig[5] , &s[8] );
	pack_40b_31x8( &sig[10] , &s[16] );
	pack_40b_31x8( &sig[15] , &s[24] );
	pack_40b_31x8( &sig[20] , &s[32] );
	pack_40b_31x8( &sig[25] , &s[40] );
	pack_40b_31x8( &sig[30] , &s[48] );
	pack_40b_31x8( &sig[35] , &s[56] );
	pack_40b_31x8( &sig[40] , &s[64] );
	pack_40b_31x8( &sig[45] , &s[72] );

	return r;
}




#endif /* defined(__TTS_2__) */


