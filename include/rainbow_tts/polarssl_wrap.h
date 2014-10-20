#ifndef _POLARSSL_WRAP_H_
#define _POLARSSL_WRAP_H_

#include "run_config.h"
#include "rainbow.h"

#include "polarssl/pk_wrap.h"


#if defined(__TTS__)
typedef struct {
    qpoly_64x40_t    pk;
    tts_seckey_t     sk;
} tts_context;

extern const pk_info_t tts_info;

#endif


#if defined(__RAINBOW__)
typedef struct {
    qpoly_64x40_t    pk;
    rb_seckey_t      sk;
} rainbow_context;

extern const pk_info_t rainbow_info;

#endif

#if defined(__TTS_2__)
typedef struct {
    qpoly_80x52_t    pk;
    tts2_seckey_t    sk;
} tts2_context;

extern const pk_info_t tts2_info;

#endif


#if defined(__RAINBOW_2__)
typedef struct {
    qpoly_80x52_t    pk;
    rb2_seckey_t     sk;
} rainbow2_context;

extern const pk_info_t rainbow2_info;

#endif



#endif /* _POLARSSL_WRAP_H_ */
