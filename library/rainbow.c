#include "rainbow_tts/run_config.h"

#include "rainbow_tts/rainbow.h"

#include "rainbow_tts/linear31.h"

#include "rainbow_tts/_hash_sha256.h"



#if defined(__TTS__)
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
	vec_rand( sk->l1_coefsigma , 24 , f_rng , p_rng );
	vec_rand( sk->l1_coefsigma , 24 , f_rng , p_rng );
	for(i=0;i<44;i++) idx[i]=i;
	vec_shuffle(idx,24, f_rng , p_rng );
	vec_assign( sk->l1_sigma , idx , 24 );
	for(i=0;i<20;i++) {
		vec_shuffle(idx,24, f_rng , p_rng );
		vec_assign( sk->l1_pi[i] , idx , 24 );
	}
	vec_shuffle(idx,44, f_rng , p_rng );
	vec_assign( sk->l2_sigma , idx , 44 );
	for(i=0;i<20;i++) {
		vec_shuffle(idx,44, f_rng , p_rng );
		vec_assign( sk->l2_pi[i] , idx , 44 );
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
		badluck = solve_linear20( &tmp[24] , &rowmat[0][0] , tmp3 );
		if( 0 != badluck ) continue;

		calc_constant2( tmp3 , key , tmp );
		vec_negative( tmp3 , tmp3 , 20 );
		vec_add( tmp3 , &tmp2[20] , 20 );
		gen_ov_rowmat2( rowmat , key , tmp );
/* __TTS__ */
		badluck = solve_linear20( &tmp[44] , &rowmat[0][0] , tmp3 );
		if( 0 == badluck ) break;
	}
	if( 0 != badluck ) return -1;

	vec_add(tmp, key->sc , 64 );
	vec_setzero((uint8_t *)r32,64*4);
	mat_mad32( r32 , &key->s[0][0] , tmp , 64 );
	vec_fullreduce32_cvt( s , r32 , 64 );

	vec_fullreduce( s , 40 ); /* remove 31 */
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
		badluck = solve_linear20( &tmp[24] , &rowmat[0][0] , tmp3 );
		if( 0 != badluck ) continue;

		eval_q44x20( tmp3 , &(key->vv2nd) , tmp );
		vec_negative( tmp3 , tmp3 , 20 );
		vec_add( tmp3 , &tmp2[20] , 20 );
		gen_ov_rowmat( rowmat , key->ol2nd_rowmat , & key->ov2nd_rowmat[0][0][0] , tmp , 44 );
/* __RAINBOW__ */
		badluck = solve_linear20( &tmp[44] , &rowmat[0][0] , tmp3 );
		if( 0 == badluck ) break;
	}
	if( 0 != badluck ) return -1;

	vec_add(tmp, key->sc , 64 );
	vec_setzero((uint8_t *)r32,64*4);
	mat_mad32( r32 , &key->s[0][0] , tmp , 64 );
	vec_fullreduce32_cvt( s , r32 , 64 );

	vec_fullreduce( s , 40 ); /* remove 31 */
	return 0;
}



#endif /* defined(__RAINBOW__) */



static inline int verify( const uint8_t * md , const qpoly_64x40_t * key , const uint8_t * s )
{
	uint8_t r[40];
	eval_q64x40( r , key , s );
	return vec_cmp40(md,r);
}



static void pack_qpoly_64x40( uint8_t *pubkey , const uint8_t * qp )
{
	unsigned i;
	for(i=0;i<sizeof(qpoly_64x40_t)/8;i++){
		pack_40b_31x8( pubkey , qp );
		pubkey += 5;
		qp += 8;
	}
}




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




