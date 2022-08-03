/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_SM4
# include <openssl/evp.h>
# include <openssl/modes.h>
# include "internal/sm4.h"
# include "internal/evp_int.h"

typedef struct {
    SM4_KEY ks;
} EVP_SM4_KEY;

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    printf("ddddddddddd sm4_init_key \n");
    SM4_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

static void sm4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const SM4_KEY *key,
                            unsigned char *ivec, const int enc)
{
    printf("ddddddddddd sm4_cbc_encrypt \n");
    if (enc)
        CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
                              (block128_f)SM4_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
                              (block128_f)SM4_decrypt);
}

static void sm4_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                               size_t length, const SM4_KEY *key,
                               unsigned char *ivec, int *num, const int enc)
{
    printf("ddddddddddd sm4_cfb128_encrypt \n");
    CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc,
                          (block128_f)SM4_encrypt);
}

static void sm4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                            const SM4_KEY *key, const int enc)
{
    printf("ddddddddddd sm4_ecb_encrypt \n");
    if (enc)
        SM4_encrypt(in, out, key);
    else
        SM4_decrypt(in, out, key);
}

static void sm4_ofb128_encrypt(const unsigned char *in, unsigned char *out,
                               size_t length, const SM4_KEY *key,
                               unsigned char *ivec, int *num)
{
    printf("ddddddddddd sm4_ofb128_encrypt \n");
    CRYPTO_ofb128_encrypt(in, out, length, key, ivec, num,
                          (block128_f)SM4_encrypt);
}


static int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) 
{ 
    printf("ddddddddddd sm4_cbc_cipher \n");
    while(inl>=EVP_MAXCHUNK) 
    { 
        sm4_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(EVP_SM4_KEY,ctx)->ks, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx)); inl-=EVP_MAXCHUNK; in +=EVP_MAXCHUNK; out+=EVP_MAXCHUNK; 
    } 
    if (inl) 
        sm4_cbc_encrypt(in, out, (long)inl, &EVP_C_DATA(EVP_SM4_KEY,ctx)->ks, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx)); return 1;
} 
static int sm4_cfb128_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) 
{ 
    printf("ddddddddddd sm4_cfb128_cipher \n");
    size_t chunk = EVP_MAXCHUNK; 
    if (128 == 1) chunk >>= 3; 
    if (inl < chunk) chunk = inl; 
    while (inl && inl >= chunk) 
    { 
        int num = EVP_CIPHER_CTX_num(ctx); 
        sm4_cfb128_encrypt(in, out, (long) ((128 == 1) && !EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) ? chunk*8 : chunk), &EVP_C_DATA(EVP_SM4_KEY, ctx)->ks, EVP_CIPHER_CTX_iv_noconst(ctx), &num, EVP_CIPHER_CTX_encrypting(ctx)); 
        EVP_CIPHER_CTX_set_num(ctx, num); 
        inl -= chunk; 
        in += chunk; 
        out += chunk; 
        if (inl < chunk) chunk = inl; 
    } 
    return 1;
}
static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) 
{ 
    printf("ddddddddddd sm4_ecb_cipher \n");
    size_t i, bl; 
    bl = EVP_CIPHER_CTX_cipher(ctx)->block_size; 
    if (inl < bl) return 1; 
    inl -= bl; 
    for (i=0; i <= inl; i+=bl) 
        sm4_ecb_encrypt(in + i, out + i, &EVP_C_DATA(EVP_SM4_KEY,ctx)->ks, EVP_CIPHER_CTX_encrypting(ctx)); 
    return 1;
} 
static int sm4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{ 
    printf("ddddddddddd sm4_ofb_cipher \n");
    while(inl>=EVP_MAXCHUNK) 
    { 
        int num = EVP_CIPHER_CTX_num(ctx); 
        sm4_ofb128_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(EVP_SM4_KEY,ctx)->ks, EVP_CIPHER_CTX_iv_noconst(ctx), &num); 
        EVP_CIPHER_CTX_set_num(ctx, num); inl-=EVP_MAXCHUNK; in +=EVP_MAXCHUNK; out+=EVP_MAXCHUNK; 
    } 
    if (inl) 
    { 
        int num = EVP_CIPHER_CTX_num(ctx); 
        sm4_ofb128_encrypt(in, out, (long)inl, &EVP_C_DATA(EVP_SM4_KEY,ctx)->ks, EVP_CIPHER_CTX_iv_noconst(ctx), &num); 
        EVP_CIPHER_CTX_set_num(ctx, num); 
    } 
    return 1;
}

static const EVP_CIPHER sm4_cbc = { 
    NID_sm4_cbc, 16, 16, 16, 0x1000 | EVP_CIPH_CBC_MODE, sm4_init_key, sm4_cbc_cipher, 0, sizeof(EVP_SM4_KEY), 0, 0, 0, NULL 
}; 
const EVP_CIPHER *EVP_sm4_cbc(void)
{
     printf("ddddddddddd EVP_sm4_cbc \n");
    return &sm4_cbc;
}
static const EVP_CIPHER sm4_cfb128 = { 
    NID_sm4_cfb128, 1, 16, 16, 0x1000 | EVP_CIPH_CFB_MODE, sm4_init_key, sm4_cfb128_cipher, 0, sizeof(EVP_SM4_KEY), 0, 0, 0, NULL 
}; 
const EVP_CIPHER *EVP_sm4_cfb128(void)
{
    printf("ddddddddddd EVP_sm4_cfb128 \n");
    return &sm4_cfb128;
}
static const EVP_CIPHER sm4_ofb = { 
    NID_sm4_ofb128, 1, 16, 16, 0x1000 | EVP_CIPH_OFB_MODE, sm4_init_key, sm4_ofb_cipher, 0, sizeof(EVP_SM4_KEY), 0, 0, 0, NULL 
}; 
const EVP_CIPHER *EVP_sm4_ofb(void)
{
    printf("ddddddddddd EVP_sm4_ofb \n");
    return &sm4_ofb;
}
static const EVP_CIPHER sm4_ecb = { 
    NID_sm4_ecb, 16, 16, 0, 0x1000 | EVP_CIPH_ECB_MODE, sm4_init_key, sm4_ecb_cipher, 0, sizeof(EVP_SM4_KEY), 0, 0, 0, NULL 
}; 
const EVP_CIPHER *EVP_sm4_ecb(void)
{
    printf("ddddddddddd EVP_sm4_ecb \n");
    return &sm4_ecb;
}

static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    printf("ddddddddddd sm4_ctr_cipher \n");
    unsigned int num = EVP_CIPHER_CTX_num(ctx);
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY, ctx);

    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks,
                          EVP_CIPHER_CTX_iv_noconst(ctx),
                          EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                          (block128_f)SM4_encrypt);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static const EVP_CIPHER sm4_ctr_mode = {
    NID_sm4_ctr, 1, 16, 16,
    EVP_CIPH_CTR_MODE,
    sm4_init_key,
    sm4_ctr_cipher,
    NULL,
    sizeof(EVP_SM4_KEY),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sm4_ctr(void)
{
    printf("ddddddddddd EVP_sm4_ctr \n");
    return &sm4_ctr_mode;
}


typedef struct {
	block128_f block;
	union {
		cbc128_f cbc;
		ctr128_f ctr;
	} stream;
	GMold_sms4_key_t ks;
} GMold_EVP_SMS4_KEY;


void GMold_sms4_cbc_encrypt(const unsigned char *in, unsigned char *out,
	size_t len, const GMold_sms4_key_t *key, unsigned char *iv, int enc)
{
	if (enc)
		CRYPTO_cbc128_encrypt(in, out, len, key, iv, (block128_f)GMold_sms4_encrypt);
	else	
        CRYPTO_cbc128_decrypt(in, out, len, key, iv, (block128_f)GMold_sms4_encrypt);
}

static int GMold_sms4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
	const unsigned char *iv, int enc)
{
	int mode;
	GMold_EVP_SMS4_KEY *dat = EVP_C_DATA(GMold_EVP_SMS4_KEY, ctx);
	mode = EVP_CIPHER_CTX_mode(ctx);

	if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
		GMold_sms4_set_decrypt_key(&dat->ks, key);
	} else {
		GMold_sms4_set_encrypt_key(&dat->ks, key);
	}
	dat->block = (block128_f)GMold_sms4_encrypt;
	dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ? (cbc128_f) GMold_sms4_cbc_encrypt : NULL;

	return 1;
}

static int GMold_sms4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) 
{ 
	while(inl>=EVP_MAXCHUNK) 
	{ 
		GMold_sms4_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &EVP_C_DATA(GMold_EVP_SMS4_KEY,ctx)->ks, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx)); 
		inl-=EVP_MAXCHUNK; 
        in +=EVP_MAXCHUNK; 
        out+=EVP_MAXCHUNK; 
	} 
	if (inl) 
		GMold_sms4_cbc_encrypt(in, out, (long)inl, &EVP_C_DATA(GMold_EVP_SMS4_KEY,ctx)->ks, EVP_CIPHER_CTX_iv_noconst(ctx), EVP_CIPHER_CTX_encrypting(ctx)); 
    return 1;
} 

static const EVP_CIPHER GMold_sms4_cbc = 
{ 
	1103, 16, 16, (16), 0 | EVP_CIPH_CBC_MODE, 
	GMold_sms4_init_key, GMold_sms4_cbc_cipher, ((void *)0), sizeof(GMold_EVP_SMS4_KEY), 
	((void *)0), ((void *)0), ((void *)0), NULL 
}; 
const EVP_CIPHER *GMold_EVP_sms4_cbc(void) 
{ 
    return &GMold_sms4_cbc; 
} 

#endif
