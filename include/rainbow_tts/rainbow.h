
#ifndef _RAINBOW_H_
#define _RAINBOW_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "run_config.h"
#include "linear31.h"



/* TTS public interface */


#if defined(__TTS__)

typedef struct {
uint8_t extra_random[32];
uint8_t s[64][64];
uint8_t sc[64];
uint8_t l1_sigma[24];
uint8_t l1_coefsigma[24];
uint8_t l1_pi[20][24];
uint8_t l1_coefpi[20][22];
uint8_t l2_sigma[44];
uint8_t l2_coefsigma[44];
uint8_t l2_pi[20][44];
uint8_t l2_coefpi[20][42];
uint8_t t[40][40];
uint8_t tc[40];
} tts_seckey_t;

#endif /*  __TTS__ */


#define TTS_SECKEY_SIZE_BYTE 8608
#define TTS_PUBKEY_SIZE_BYTE 53600
#define TTS_DIGEST_SIZE_BYTE 24
#define TTS_SIGNATURE_SIZE_BYTE 40


int tts_genkey( uint8_t * pubkey , uint8_t *seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int tts_sign( uint8_t * s320b , const uint8_t * key , const uint8_t * md192b );

int tts_verify( const uint8_t * md192b , const uint8_t * key , const uint8_t * s320b );





/* rainbow public interface */


#if defined(__RAINBOW__)

typedef struct {
uint8_t s[64][64];
uint8_t sc[64];
qpoly_24x20_t vv1st;
uint8_t ov1st_rowmat[20][20][24];
uint8_t ol1st_rowmat[20][20];
qpoly_44x20_t vv2nd;
uint8_t ov2nd_rowmat[20][20][44];
uint8_t ol2nd_rowmat[20][20];
uint8_t t[40][40];
uint8_t tc[40];
} rb_seckey_t;

#endif /* __RAINBOW__ */


#define RB_SECKEY_SIZE_BYTE 60960
#define RB_PUBKEY_SIZE_BYTE TTS_PUBKEY_SIZE_BYTE
#define RB_DIGEST_SIZE_BYTE TTS_DIGEST_SIZE_BYTE
#define RB_SIGNATURE_SIZE_BYTE TTS_SIGNATURE_SIZE_BYTE


int rb_genkey( uint8_t * pubkey , uint8_t *seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int rb_sign( uint8_t * s320b , const uint8_t * key , const uint8_t * md192b );

#define rb_verify tts_verify




#if defined(__RAINBOW_2__)

typedef struct {
uint8_t s[80][80];
uint8_t sc[80];
qpoly_26x24_t vv1st;
uint8_t ov1st_rowmat[24][24][26];
uint8_t ol1st_rowmat[24][24];
qpoly_52x4_t vv2nd;
uint8_t ov2nd_rowmat[4][4][52];
uint8_t ol2nd_rowmat[4][4];
qpoly_56x24_t vv3rd;
uint8_t ov3rd_rowmat[24][24][56];
uint8_t ol3rd_rowmat[24][24];
uint8_t t[52][52];
uint8_t tc[52];
} rb2_seckey_t;

#endif /* __RAINBOW_2__ */


#define RB2_SECKEY_SIZE_BYTE sizeof(rb2_seckey_t)
#define RB2_PUBKEY_SIZE_BYTE (sizeof(qpoly_80x52_t)*5/8)
#define RB2_DIGEST_SIZE_BYTE 32
#define RB2_SIGNATURE_SIZE_BYTE 50


int rb2_genkey( uint8_t * pubkey , uint8_t *seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int rb2_sign( uint8_t * sig , const uint8_t * seckey , const uint8_t * md );

int rb2_verify( const uint8_t * md , const uint8_t * pubkey , const uint8_t * sig );







#if defined(__TTS_2__)

typedef struct {
uint8_t extra_random[32];
uint8_t s[80][80];
uint8_t sc[80];
//        l1: v26, o24  linear: idx: 26 coef: 26   quad: 24x( idx:26 , coef: 25 (ov:24,vv:1) )
//        l2: v52, o4   linear: idx: 52 coef: 52   quad:  4x( idx:52 , coef: 36 (ov: 4x5=20, vv: 32/2=16) )
//        l3: v56, o24  linear: idx: 56 coef: 56   quad: 24x( idx:56 , coef: 52 (ov:24x2=48, vv: 8/2=4) )
uint8_t l1_sigma[26];
uint8_t l1_coefsigma[26];
uint8_t l1_pi[24][26];
uint8_t l1_coefpi[24][25];
uint8_t l2_sigma[52];
uint8_t l2_coefsigma[52];
uint8_t l2_pi[4][52];
uint8_t l2_coefpi[4][36];
uint8_t l3_sigma[56];
uint8_t l3_coefsigma[56];
uint8_t l3_pi[24][56];
uint8_t l3_coefpi[24][52];
//qpoly_26x24_t vv1st;
//uint8_t ov1st_rowmat[24][24][26];
//uint8_t ol1st_rowmat[24][24];
//qpoly_52x4_t vv2nd;
//uint8_t ov2nd_rowmat[4][4][52];
//uint8_t ol2nd_rowmat[4][4];
//qpoly_56x24_t vv3rd;
//uint8_t ov3rd_rowmat[24][24][56];
//uint8_t ol3rd_rowmat[24][24];
uint8_t t[52][52];
uint8_t tc[52];
} tts2_seckey_t;

#endif /* __TTS_2__ */


#define TTS2_SECKEY_SIZE_BYTE sizeof(tts2_seckey_t)
#define TTS2_PUBKEY_SIZE_BYTE (sizeof(qpoly_80x52_t)*5/8)
#define TTS2_DIGEST_SIZE_BYTE 32
#define TTS2_SIGNATURE_SIZE_BYTE 50


int tts2_genkey( uint8_t * pubkey , uint8_t *seckey , int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int tts2_sign( uint8_t * sig , const uint8_t * seckey , const uint8_t * md );

#define tts2_verify rb2_verify



#if defined(__POLARSSL__)
#include "polarssl_wrap.h"
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RAIDBOW_H_ */



