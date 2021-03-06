/**
 * \file ssl_ciphersuites.h
 *
 * \brief SSL Ciphersuites for PolarSSL
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef POLARSSL_SSL_CIPHERSUITES_H
#define POLARSSL_SSL_CIPHERSUITES_H

#include "pk.h"
#include "cipher.h"
#include "md.h"

#include "dh.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Supported ciphersuites (Official IANA names)
 */
#define TLS_RSA_WITH_NULL_MD5                    0x01   /**< Weak! */
#define TLS_RSA_WITH_NULL_SHA                    0x02   /**< Weak! */

#define TLS_RSA_WITH_RC4_128_MD5                 0x04
#define TLS_RSA_WITH_RC4_128_SHA                 0x05
#define TLS_RSA_WITH_DES_CBC_SHA                 0x09   /**< Weak! Not in TLS 1.2 */

#define TLS_RSA_WITH_3DES_EDE_CBC_SHA            0x0A

#define TLS_DHE_RSA_WITH_DES_CBC_SHA             0x15   /**< Weak! Not in TLS 1.2 */
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA        0x16

#define TLS_PSK_WITH_NULL_SHA                    0x2C   /**< Weak! */
#define TLS_DHE_PSK_WITH_NULL_SHA                0x2D   /**< Weak! */
#define TLS_RSA_PSK_WITH_NULL_SHA                0x2E   /**< Weak! */
#define TLS_RSA_WITH_AES_128_CBC_SHA             0x2F

#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA         0x33
#define TLS_RSA_WITH_AES_256_CBC_SHA             0x35
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA         0x39

#define TLS_RSA_WITH_NULL_SHA256                 0x3B   /**< Weak! */
#define TLS_RSA_WITH_AES_128_CBC_SHA256          0x3C   /**< TLS 1.2 */
#define TLS_RSA_WITH_AES_256_CBC_SHA256          0x3D   /**< TLS 1.2 */

#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA        0x41
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA    0x45

#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256      0x67   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256      0x6B   /**< TLS 1.2 */

#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA        0x84
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA    0x88

#define TLS_PSK_WITH_RC4_128_SHA                 0x8A
#define TLS_PSK_WITH_3DES_EDE_CBC_SHA            0x8B
#define TLS_PSK_WITH_AES_128_CBC_SHA             0x8C
#define TLS_PSK_WITH_AES_256_CBC_SHA             0x8D

#define TLS_DHE_PSK_WITH_RC4_128_SHA             0x8E
#define TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA        0x8F
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA         0x90
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA         0x91

#define TLS_RSA_PSK_WITH_RC4_128_SHA             0x92
#define TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA        0x93
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA         0x94
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA         0x95

#define TLS_RSA_WITH_AES_128_GCM_SHA256          0x9C   /**< TLS 1.2 */
#define TLS_RSA_WITH_AES_256_GCM_SHA384          0x9D   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256      0x9E   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384      0x9F   /**< TLS 1.2 */

#define TLS_PSK_WITH_AES_128_GCM_SHA256          0xA8   /**< TLS 1.2 */
#define TLS_PSK_WITH_AES_256_GCM_SHA384          0xA9   /**< TLS 1.2 */
#define TLS_DHE_PSK_WITH_AES_128_GCM_SHA256      0xAA   /**< TLS 1.2 */
#define TLS_DHE_PSK_WITH_AES_256_GCM_SHA384      0xAB   /**< TLS 1.2 */
#define TLS_RSA_PSK_WITH_AES_128_GCM_SHA256      0xAC   /**< TLS 1.2 */
#define TLS_RSA_PSK_WITH_AES_256_GCM_SHA384      0xAD   /**< TLS 1.2 */

#define TLS_PSK_WITH_AES_128_CBC_SHA256          0xAE
#define TLS_PSK_WITH_AES_256_CBC_SHA384          0xAF
#define TLS_PSK_WITH_NULL_SHA256                 0xB0   /**< Weak! */
#define TLS_PSK_WITH_NULL_SHA384                 0xB1   /**< Weak! */

#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA256      0xB2
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA384      0xB3
#define TLS_DHE_PSK_WITH_NULL_SHA256             0xB4   /**< Weak! */
#define TLS_DHE_PSK_WITH_NULL_SHA384             0xB5   /**< Weak! */

#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA256      0xB6
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA384      0xB7
#define TLS_RSA_PSK_WITH_NULL_SHA256             0xB8   /**< Weak! */
#define TLS_RSA_PSK_WITH_NULL_SHA384             0xB9   /**< Weak! */

#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256     0xBA   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 0xBE   /**< TLS 1.2 */

#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256     0xC0   /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 0xC4   /**< TLS 1.2 */

#define TLS_ECDH_ECDSA_WITH_NULL_SHA             0xC001 /**< Weak! */
#define TLS_ECDH_ECDSA_WITH_RC4_128_SHA          0xC002 /**< Not in SSL3! */
#define TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA     0xC003 /**< Not in SSL3! */
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA      0xC004 /**< Not in SSL3! */
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA      0xC005 /**< Not in SSL3! */

#define TLS_ECDHE_ECDSA_WITH_NULL_SHA            0xC006 /**< Weak! */
#define TLS_ECDHE_ECDSA_WITH_RC4_128_SHA         0xC007 /**< Not in SSL3! */
#define TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA    0xC008 /**< Not in SSL3! */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA     0xC009 /**< Not in SSL3! */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA     0xC00A /**< Not in SSL3! */

#define TLS_ECDH_RSA_WITH_NULL_SHA               0xC00B /**< Weak! */
#define TLS_ECDH_RSA_WITH_RC4_128_SHA            0xC00C /**< Not in SSL3! */
#define TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA       0xC00D /**< Not in SSL3! */
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA        0xC00E /**< Not in SSL3! */
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA        0xC00F /**< Not in SSL3! */

#define TLS_ECDHE_RSA_WITH_NULL_SHA              0xC010 /**< Weak! */
#define TLS_ECDHE_RSA_WITH_RC4_128_SHA           0xC011 /**< Not in SSL3! */
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA      0xC012 /**< Not in SSL3! */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA       0xC013 /**< Not in SSL3! */
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA       0xC014 /**< Not in SSL3! */

#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256  0xC023 /**< TLS 1.2 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384  0xC024 /**< TLS 1.2 */
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256   0xC025 /**< TLS 1.2 */
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384   0xC026 /**< TLS 1.2 */
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256    0xC027 /**< TLS 1.2 */
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384    0xC028 /**< TLS 1.2 */
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256     0xC029 /**< TLS 1.2 */
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384     0xC02A /**< TLS 1.2 */

#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  0xC02B /**< TLS 1.2 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  0xC02C /**< TLS 1.2 */
#define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256   0xC02D /**< TLS 1.2 */
#define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384   0xC02E /**< TLS 1.2 */
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    0xC02F /**< TLS 1.2 */
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    0xC030 /**< TLS 1.2 */
#define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256     0xC031 /**< TLS 1.2 */
#define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384     0xC032 /**< TLS 1.2 */

#define TLS_ECDHE_PSK_WITH_RC4_128_SHA           0xC033 /**< Not in SSL3! */
#define TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA      0xC034 /**< Not in SSL3! */
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA       0xC035 /**< Not in SSL3! */
#define TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA       0xC036 /**< Not in SSL3! */
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256    0xC037 /**< Not in SSL3! */
#define TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384    0xC038 /**< Not in SSL3! */
#define TLS_ECDHE_PSK_WITH_NULL_SHA              0xC039 /**< Weak! No SSL3! */
#define TLS_ECDHE_PSK_WITH_NULL_SHA256           0xC03A /**< Weak! No SSL3! */
#define TLS_ECDHE_PSK_WITH_NULL_SHA384           0xC03B /**< Weak! No SSL3! */

#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 0xC072 /**< Not in SSL3! */
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 0xC073 /**< Not in SSL3! */
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  0xC074 /**< Not in SSL3! */
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  0xC075 /**< Not in SSL3! */
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   0xC076 /**< Not in SSL3! */
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   0xC077 /**< Not in SSL3! */
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    0xC078 /**< Not in SSL3! */
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    0xC079 /**< Not in SSL3! */

#define TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256         0xC07A /**< TLS 1.2 */
#define TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384         0xC07B /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256     0xC07C /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384     0xC07D /**< TLS 1.2 */
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 0xC086 /**< TLS 1.2 */
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 0xC087 /**< TLS 1.2 */
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  0xC088 /**< TLS 1.2 */
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  0xC089 /**< TLS 1.2 */
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256   0xC08A /**< TLS 1.2 */
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384   0xC08B /**< TLS 1.2 */
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256    0xC08C /**< TLS 1.2 */
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384    0xC08D /**< TLS 1.2 */

#define TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256       0xC08E /**< TLS 1.2 */
#define TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384       0xC08F /**< TLS 1.2 */
#define TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256   0xC090 /**< TLS 1.2 */
#define TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384   0xC091 /**< TLS 1.2 */
#define TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256   0xC092 /**< TLS 1.2 */
#define TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384   0xC093 /**< TLS 1.2 */

#define TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256       0xC094
#define TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384       0xC095
#define TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256   0xC096
#define TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384   0xC097
#define TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256   0xC098
#define TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384   0xC099
#define TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 0xC09A /**< Not in SSL3! */
#define TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 0xC09B /**< Not in SSL3! */

#define TLS_RSA_WITH_AES_128_CCM                0xC09C  /**< TLS 1.2 */
#define TLS_RSA_WITH_AES_256_CCM                0xC09D  /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_128_CCM            0xC09E  /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_256_CCM            0xC09F  /**< TLS 1.2 */
#define TLS_RSA_WITH_AES_128_CCM_8              0xC0A0  /**< TLS 1.2 */
#define TLS_RSA_WITH_AES_256_CCM_8              0xC0A1  /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_128_CCM_8          0xC0A2  /**< TLS 1.2 */
#define TLS_DHE_RSA_WITH_AES_256_CCM_8          0xC0A3  /**< TLS 1.2 */
#define TLS_PSK_WITH_AES_128_CCM                0xC0A4  /**< TLS 1.2 */
#define TLS_PSK_WITH_AES_256_CCM                0xC0A5  /**< TLS 1.2 */
#define TLS_DHE_PSK_WITH_AES_128_CCM            0xC0A6  /**< TLS 1.2 */
#define TLS_DHE_PSK_WITH_AES_256_CCM            0xC0A7  /**< TLS 1.2 */
#define TLS_PSK_WITH_AES_128_CCM_8              0xC0A8  /**< TLS 1.2 */
#define TLS_PSK_WITH_AES_256_CCM_8              0xC0A9  /**< TLS 1.2 */
#define TLS_DHE_PSK_WITH_AES_128_CCM_8          0xC0AA  /**< TLS 1.2 */
#define TLS_DHE_PSK_WITH_AES_256_CCM_8          0xC0AB  /**< TLS 1.2 */
/* The last two are named with PSK_DHE in the RFC, which looks like a typo */

#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM        0xC0AC  /**< TLS 1.2 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM        0xC0AD  /**< TLS 1.2 */
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8      0xC0AE  /**< TLS 1.2 */
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8      0xC0AF  /**< TLS 1.2 */

#define TLS_ECDHE_RAINBOW_WITH_AES_128_GCM_SHA256       0xCCFE /* Ours */
#define TLS_ECDHE_TTS_WITH_AES_128_GCM_SHA256           0xCCFF /* Ours */

#define TLS_LATTICEE_TTS_WITH_AES_128_GCM_SHA256        0xCC00 /* Ours */
#define TLS_LATTICEE_RAINBOW_WITH_AES_128_GCM_SHA256    0xCC01 /* Ours */
#define TLS_LATTICEE_RSA_WITH_AES_128_GCM_SHA256        0xCC02 /* Ours */
#define TLS_LATTICEE_ECDSA_WITH_AES_128_GCM_SHA256      0xCC03 /* Ours */
#define TLS_LATTICEE_TTS2_WITH_AES_128_GCM_SHA256       0xCC04 /* Ours */
#define TLS_LATTICEE_RAINBOW2_WITH_AES_128_GCM_SHA256   0xCC05 /* Ours */

#define TLS_CV25519E_TTS_WITH_AES_128_GCM_SHA256        0xCC10 /* Ours */
#define TLS_CV25519E_RAINBOW_WITH_AES_128_GCM_SHA256    0xCC11 /* Ours */
#define TLS_CV25519E_RSA_WITH_AES_128_GCM_SHA256        0xCC12 /* Ours */
#define TLS_CV25519E_ECDSA_WITH_AES_128_GCM_SHA256      0xCC13 /* Ours */
#define TLS_CV25519E_TTS2_WITH_AES_128_GCM_SHA256       0xCC14 /* Ours */
#define TLS_CV25519E_RAINBOW2_WITH_AES_128_GCM_SHA256   0xCC15 /* Ours */

/* Reminder: update _ssl_premaster_secret when adding a new key exchange */
typedef enum {
    POLARSSL_KEY_EXCHANGE_NONE = 0,
    POLARSSL_KEY_EXCHANGE_RSA,
    POLARSSL_KEY_EXCHANGE_DHE_RSA,
    POLARSSL_KEY_EXCHANGE_ECDHE_RSA,
    POLARSSL_KEY_EXCHANGE_ECDHE_ECDSA,
    POLARSSL_KEY_EXCHANGE_PSK,
    POLARSSL_KEY_EXCHANGE_DHE_PSK,
    POLARSSL_KEY_EXCHANGE_RSA_PSK,
    POLARSSL_KEY_EXCHANGE_ECDHE_PSK,
    POLARSSL_KEY_EXCHANGE_ECDH_RSA,
    POLARSSL_KEY_EXCHANGE_ECDH_ECDSA,
    OUR_KEY_EXCHANGE_ECDHE_TTS,
    OUR_KEY_EXCHANGE_ECDHE_RAINBOW,
    OUR_KEY_EXCHANGE_LATTICEE_TTS,
    OUR_KEY_EXCHANGE_LATTICEE_RAINBOW,
    OUR_KEY_EXCHANGE_LATTICEE_RSA,
    OUR_KEY_EXCHANGE_LATTICEE_ECDSA,
    OUR_KEY_EXCHANGE_LATTICEE_TTS2,
    OUR_KEY_EXCHANGE_LATTICEE_RAINBOW2,
    OUR_KEY_EXCHANGE_CV25519E_TTS,
    OUR_KEY_EXCHANGE_CV25519E_RAINBOW,
    OUR_KEY_EXCHANGE_CV25519E_RSA,
    OUR_KEY_EXCHANGE_CV25519E_ECDSA,
    OUR_KEY_EXCHANGE_CV25519E_TTS2,
    OUR_KEY_EXCHANGE_CV25519E_RAINBOW2,
} key_exchange_type_t;

typedef struct _ssl_ciphersuite_t ssl_ciphersuite_t;

#define POLARSSL_CIPHERSUITE_WEAK       0x01    /**< Weak ciphersuite flag  */
#define POLARSSL_CIPHERSUITE_SHORT_TAG  0x02    /**< Short authentication tag,
                                                     eg for CCM_8 */

/**
 * \brief   This structure is used for storing ciphersuite information
 */
struct _ssl_ciphersuite_t
{
    int id;
    const char * name;

    cipher_type_t cipher;
    md_type_t mac;
    key_exchange_type_t key_exchange;

    int min_major_ver;
    int min_minor_ver;
    int max_major_ver;
    int max_minor_ver;

    unsigned char flags;
};

const int *ssl_list_ciphersuites( void );

const ssl_ciphersuite_t *ssl_ciphersuite_from_string( const char *ciphersuite_name );
const ssl_ciphersuite_t *ssl_ciphersuite_from_id( int ciphersuite_id );

typedef struct _key_agreement_t
{
    key_exchange_type_t key_exchange;
    dh_type_t dh_alg;
    pk_type_t sig_alg;
    int pkc_enc;
    int psk_auth;
} key_agree_t;

const key_agree_t *ssl_ciphersuite_recognize( key_exchange_type_t key_exchange );


#if defined(POLARSSL_PK_C)
pk_type_t ssl_get_ciphersuite_sig_pk_alg( const ssl_ciphersuite_t *info );
#endif

int ssl_ciphersuite_uses_ec( const ssl_ciphersuite_t *info );
int ssl_ciphersuite_uses_psk( const ssl_ciphersuite_t *info );



#if defined(POLARSSL_DHIF_C)
dh_type_t ssl_ciphersuite_dh_type( key_exchange_type_t ssl_type );
int ssl_ciphersuite_is_dh_ephemeral( key_exchange_type_t ssl_type );
int ssl_ciphersuite_is_dh( key_exchange_type_t ssl_type );
int ssl_ciphersuite_is_dh_pkcsign( key_exchange_type_t ssl_type );
int ssl_ciphersuite_is_dh_psk( key_exchange_type_t ssl_type );
#endif




#ifdef __cplusplus
}
#endif

#endif /* ssl_ciphersuites.h */
