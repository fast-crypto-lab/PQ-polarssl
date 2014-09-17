
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


#ifdef __cplusplus
}
#endif

#endif /* _RAIDBOW_H_ */



