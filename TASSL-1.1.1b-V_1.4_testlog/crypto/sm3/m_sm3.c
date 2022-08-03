/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_SM3
# include <openssl/evp.h>
# include "internal/evp_int.h"
# include "internal/sm3.h"

static int init(EVP_MD_CTX *ctx)
{
    return sm3_init(EVP_MD_CTX_md_data(ctx));
}

static int GMold_init(EVP_MD_CTX *ctx)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx)) {
		return 0;
	}
	GMold_sm3_init(EVP_MD_CTX_md_data(ctx));
	return 1;
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    printf("ddddddddddd sm3_update \n");
    return sm3_update(EVP_MD_CTX_md_data(ctx), data, count);
}

static int GMold_update(EVP_MD_CTX *ctx, const void *in, size_t inlen)
{
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !in) {
		return 0;
	}
	GMold_sm3_update(EVP_MD_CTX_md_data(ctx), in, inlen);
	return 1;
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    printf("ddddddddddd sm3_final \n");
    return sm3_final(md, EVP_MD_CTX_md_data(ctx));
}

static int GMold_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    static int index = 0;
    index++;
	if (!ctx || !EVP_MD_CTX_md_data(ctx) || !md) {
		return 0;
	}
	GMold_sm3_final(EVP_MD_CTX_md_data(ctx), md);
	return 1;
}

static const EVP_MD sm3_md = {
    NID_sm3,
    NID_sm3WithRSAEncryption,
    SM3_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    SM3_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SM3_CTX),
};

static const EVP_MD GMold_sm3_md = {
    GMold_NID_sm3,
    GMold_NID_sm2sign_with_sm3,
    SM3_DIGEST_LENGTH,
    0,
    GMold_init,
    GMold_update,
    GMold_final,
    NULL,
    NULL,
    SM3_CBLOCK,
    sizeof(EVP_MD *) + sizeof(sm3_ctx_t),
};

const EVP_MD *EVP_sm3(void)
{
    printf("ddddddddddd EVP_sm3 \n");
    return &sm3_md;
}

const EVP_MD *GMold_EVP_sm3(void)
{
    return &GMold_sm3_md;
}
#endif
