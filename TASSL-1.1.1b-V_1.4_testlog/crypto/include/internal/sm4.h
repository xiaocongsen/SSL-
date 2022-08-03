/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SM4_H
# define HEADER_SM4_H

# include <openssl/opensslconf.h>
# include <openssl/e_os2.h>

# ifdef OPENSSL_NO_SM4
#  error SM4 is disabled.
# endif

# define SM4_ENCRYPT     1
# define SM4_DECRYPT     0

# define SM4_BLOCK_SIZE    16
# define SM4_KEY_SCHEDULE  32

typedef struct SM4_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

int SM4_set_key(const uint8_t *key, SM4_KEY *ks);

void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);


#define SMS4_NUM_ROUNDS		32
typedef struct {
	uint32_t rk[SMS4_NUM_ROUNDS];
} GMold_sms4_key_t;

void GMold_sms4_encrypt(const unsigned char *in, unsigned char *out, const GMold_sms4_key_t *key);
#define GMold_sms4_decrypt(in,out,key)  GMold_sms4_encrypt(in,out,key)
void GMold_sms4_set_encrypt_key(GMold_sms4_key_t *key, const unsigned char *user_key);
void GMold_sms4_set_decrypt_key(GMold_sms4_key_t *key, const unsigned char *user_key);


#endif
