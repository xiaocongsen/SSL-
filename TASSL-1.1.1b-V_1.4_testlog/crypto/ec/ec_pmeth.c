/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/ec.h>
#include "ec_lcl.h"
#include <openssl/evp.h>
#include "internal/evp_int.h"
#include <openssl/obj_mac.h>
#include <openssl/GMold_obj_mac.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
/* EC pkey context structure */

typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Duplicate key if custom cofactor needed */
    EC_KEY *co_key;
    /* Cofactor mode */
    signed char cofactor_mode;
    /* KDF (if any) to use for ECDH */
    char kdf_type;
    /* Message digest to use for key derivation */
    const EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;

    #ifndef OPENSSL_NO_CNSM
    /* server tag */
    int server;
    /* peer uid */
    char *peer_id;
    /* self uid */
    char *self_id;
    /* peer uid length */
    int peerid_len;
    /* self uid length */
    int selfid_len;
    /* peer ephemeral public key */
    EC_KEY *peer_ecdhe_key;
    /* self ephemeral key */
    EC_KEY *self_ecdhe_key;
    /* sm2/ecc encrypt out format, 0 for ASN1 */
    int encdata_format;
    #endif

} EC_PKEY_CTX;

#ifndef OPENSSL_NO_CNSM

int SM2Kap_compute_key(void *out, size_t outlen, int server,\
    const char *peer_uid, int peer_uid_len, const char *self_uid, int self_uid_len, \
    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key, const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, \
    const EVP_MD *md);

#endif

static int pkey_ec_init(EVP_PKEY_CTX *ctx)
{
    printf("dddddddddddd pkey_ec_init\n");
    EC_PKEY_CTX *dctx;

    if ((dctx = OPENSSL_zalloc(sizeof(*dctx))) == NULL) {
        ECerr(EC_F_PKEY_EC_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    dctx->cofactor_mode = -1;
    dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
    ctx->data = dctx;
    return 1;
}

static int pkey_ec_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    printf("dddddddddddd pkey_ec_copy\n");
    EC_PKEY_CTX *dctx, *sctx;
    if (!pkey_ec_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->gen_group) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (!dctx->gen_group)
            return 0;
    }
    dctx->md = sctx->md;

    if (sctx->co_key) {
        dctx->co_key = EC_KEY_dup(sctx->co_key);
        if (!dctx->co_key)
            return 0;
    }
    dctx->kdf_type = sctx->kdf_type;
    dctx->kdf_md = sctx->kdf_md;
    dctx->kdf_outlen = sctx->kdf_outlen;
    if (sctx->kdf_ukm) {
        dctx->kdf_ukm = OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
        if (!dctx->kdf_ukm)
            return 0;
    } else
        dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = sctx->kdf_ukmlen;
    return 1;
}

static void pkey_ec_cleanup(EVP_PKEY_CTX *ctx)
{
    printf("dddddddddddd pkey_ec_cleanup\n");
    EC_PKEY_CTX *dctx = ctx->data;
    if (dctx != NULL) {
        EC_GROUP_free(dctx->gen_group);
        EC_KEY_free(dctx->co_key);
        OPENSSL_free(dctx->kdf_ukm);
        OPENSSL_free(dctx);
        ctx->data = NULL;
    }
}

static int pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    printf("dddddddddddd pkey_ec_sign\n");
    int ret, type;
    unsigned int sltmp;
    EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;
    const int sig_sz = ECDSA_size(ec);

    /* ensure cast to size_t is safe */
    if (!ossl_assert(sig_sz > 0))
        return 0;

    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        ECerr(EC_F_PKEY_EC_SIGN, EC_R_BUFFER_TOO_SMALL);
        return 0;
    }

    type = (dctx->md != NULL) ? EVP_MD_type(dctx->md) : NID_sha1;

    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int pkey_ec_verify(EVP_PKEY_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    printf("dddddddddddd pkey_ec_verify\n");
    int ret, type;
    EC_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

    ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);

    return ret;
}

#ifndef OPENSSL_NO_EC
static int pkey_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    int ret;
    size_t outlen;
    const EC_POINT *pubkey = NULL;
    EC_KEY *eckey;
    EC_PKEY_CTX *dctx = ctx->data;
    if (!ctx->pkey || !ctx->peerkey) {
        ECerr(EC_F_PKEY_EC_DERIVE, EC_R_KEYS_NOT_SET);
        return 0;
    }

    eckey = dctx->co_key ? dctx->co_key : ctx->pkey->pkey.ec;

    if (!key) {
        const EC_GROUP *group;
        group = EC_KEY_get0_group(eckey);
        *keylen = (EC_GROUP_get_degree(group) + 7) / 8;
        return 1;
    }
    pubkey = EC_KEY_get0_public_key(ctx->peerkey->pkey.ec);

    /*
     * NB: unlike PKCS#3 DH, if *outlen is less than maximum size this is not
     * an error, the result is truncated.
     */

    outlen = *keylen;

    ret = ECDH_compute_key(key, outlen, pubkey, eckey, 0);
    if (ret <= 0)
        return 0;
    *keylen = ret;
    return 1;
}

#ifndef OPENSSL_NO_CNSM
/*this function only used to SM2Kap*/
static int pkey_ec_sm2dh_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
    size_t *keylen)
{
    int ret;
    size_t outlen;
    EC_PKEY_CTX *dctx = ctx->data;

    if (!ctx->pkey || !ctx->peerkey)
    {
        ECerr(EC_F_PKEY_EC_SM2DH_DERIVE, EC_R_KEYS_NOT_SET);
        return 0;
    }

    if (!key || (*keylen == 0))
    {
        ECerr(EC_F_PKEY_EC_SM2DH_DERIVE, EC_R_MISSING_PARAMETERS);
        return 0;
    }

    outlen = *keylen;
#ifdef GU_DEBUG
    unsigned char *self_pub = NULL;
    unsigned char self_priv[64] = {0};
    unsigned char *self_tmp_pub = NULL;
    unsigned char self_tmp_priv[64] = {0};
    unsigned char *peer_pub = NULL;
    unsigned char *peer_tmp_pub = NULL;
    int i = 0;
    
    printf("self_priv:");
    EC_KEY_priv2oct(ctx->pkey->pkey.ec, self_priv, 64);
    for(i=0; i<32; i++){
    	printf("%02X", *(self_priv+i));
    }
    printf("\n");
    
    printf("self_pub:");
    EC_KEY_key2buf(ctx->pkey->pkey.ec, EC_KEY_get_conv_form(ctx->pkey->pkey.ec), &self_pub, NULL);
    for(i=0; i<65; i++){
    	printf("%02X", *(self_pub+i));
    }
    printf("\n");
    
    printf("self_tmp_priv:");
    EC_KEY_priv2oct(dctx->self_ecdhe_key, self_tmp_priv, 64);
    for(i=0; i<32; i++){
    	printf("%02X", *(self_tmp_priv+i));
    }
    printf("\n");
    
    printf("self_tmp_pub:");
    EC_KEY_key2buf(dctx->self_ecdhe_key, EC_KEY_get_conv_form(dctx->self_ecdhe_key), &self_tmp_pub, NULL);
    for(i=0; i<65; i++){
    	printf("%02X", *(self_tmp_pub+i));
    }
    printf("\n");
    
    printf("peer_pub:");
    EC_KEY_key2buf(ctx->peerkey->pkey.ec, EC_KEY_get_conv_form(ctx->peerkey->pkey.ec), &peer_pub, NULL);
    for(i=0; i<65; i++){
    	printf("%02X", *(peer_pub+i));
    }
    printf("\n");
    
    printf("peer_tmp_pub:");
    EC_KEY_key2buf(dctx->peer_ecdhe_key, EC_KEY_get_conv_form(dctx->peer_ecdhe_key), &peer_tmp_pub, NULL);
    for(i=0; i<65; i++){
    	printf("%02X", *(peer_tmp_pub+i));
    }
    printf("\n");
    
#endif
    ret = SM2Kap_compute_key(key, outlen, dctx->server, dctx->peer_id, dctx->peerid_len, dctx->self_id, dctx->selfid_len, \
        dctx->peer_ecdhe_key, dctx->self_ecdhe_key, ctx->peerkey->pkey.ec, ctx->pkey->pkey.ec, dctx->kdf_md);

#ifdef TASSL_DEBUG
    printf("exchange key:");
    for(i=0; i<outlen; i++){
    	printf("%02X", *(key+i));
    }
    printf("\n");
    
#endif
    if (ret <= 0)
        return 0;
    return 1;
}
#endif

static int pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx,
                              unsigned char *key, size_t *keylen)
{
    printf("dddddddddddd pkey_ec_kdf_derive\n");
    EC_PKEY_CTX *dctx = ctx->data;
    unsigned char *ktmp = NULL;
    size_t ktmplen;
    int rv = 0;

    #ifndef OPENSSL_NO_CNSM
    if (EC_GROUP_get_curve_name(EC_KEY_get0_group(ctx->pkey->pkey.ec)) == NID_sm2)
    {
        /*to SM2DH or SM2KAP*/
        return pkey_ec_sm2dh_derive(ctx, key, keylen);
    }
    #endif
	
    if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE)
        return pkey_ec_derive(ctx, key, keylen);
    if (!key) {
        *keylen = dctx->kdf_outlen;
        return 1;
    }
    if (*keylen != dctx->kdf_outlen)
        return 0;
    if (!pkey_ec_derive(ctx, NULL, &ktmplen))
        return 0;
    if ((ktmp = OPENSSL_malloc(ktmplen)) == NULL) {
        ECerr(EC_F_PKEY_EC_KDF_DERIVE, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (!pkey_ec_derive(ctx, ktmp, &ktmplen))
        goto err;
    /* Do KDF stuff */
    if (!ecdh_KDF_X9_63(key, *keylen, ktmp, ktmplen,
                        dctx->kdf_ukm, dctx->kdf_ukmlen, dctx->kdf_md))
        goto err;
    rv = 1;

 err:
    OPENSSL_clear_free(ktmp, ktmplen);
    return rv;
}
#endif

static int pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    printf("dddddddddddd pkey_ec_ctrl\n");
    EC_PKEY_CTX *dctx = ctx->data;
    EC_GROUP *group;
    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(dctx->gen_group);
        dctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (!dctx->gen_group) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_NO_PARAMETERS_SET);
            return 0;
        }
        EC_GROUP_set_asn1_flag(dctx->gen_group, p1);
        return 1;

#ifndef OPENSSL_NO_EC
    case EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
        if (p1 == -2) {
            if (dctx->cofactor_mode != -1)
                return dctx->cofactor_mode;
            else {
                EC_KEY *ec_key = ctx->pkey->pkey.ec;
                return EC_KEY_get_flags(ec_key) & EC_FLAG_COFACTOR_ECDH ? 1 : 0;
            }
        } else if (p1 < -1 || p1 > 1)
            return -2;
        dctx->cofactor_mode = p1;
        if (p1 != -1) {
            EC_KEY *ec_key = ctx->pkey->pkey.ec;
            if (!ec_key->group)
                return -2;
            /* If cofactor is 1 cofactor mode does nothing */
            if (BN_is_one(ec_key->group->cofactor))
                return 1;
            if (!dctx->co_key) {
                dctx->co_key = EC_KEY_dup(ec_key);
                if (!dctx->co_key)
                    return 0;
            }
            if (p1)
                EC_KEY_set_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
            else
                EC_KEY_clear_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
        } else {
            EC_KEY_free(dctx->co_key);
            dctx->co_key = NULL;
        }
        return 1;
#endif

    case EVP_PKEY_CTRL_EC_KDF_TYPE:
        if (p1 == -2)
            return dctx->kdf_type;
        if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_63)
            return -2;
        dctx->kdf_type = p1;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_MD:
        dctx->kdf_md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_MD:
        *(const EVP_MD **)p2 = dctx->kdf_md;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
        if (p1 <= 0)
            return -2;
        dctx->kdf_outlen = (size_t)p1;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
        *(int *)p2 = dctx->kdf_outlen;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_UKM:
        OPENSSL_free(dctx->kdf_ukm);
        dctx->kdf_ukm = p2;
        if (p2)
            dctx->kdf_ukmlen = p1;
        else
            dctx->kdf_ukmlen = 0;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_UKM:
        *(unsigned char **)p2 = dctx->kdf_ukm;
        return dctx->kdf_ukmlen;

    case EVP_PKEY_CTRL_MD:
        if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_ecdsa_with_SHA1 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha512 
            #ifndef OPENSSL_NO_CNSM
            && EVP_MD_type((const EVP_MD *)p2) != NID_sm3
            #endif
                                                         ) {
            ECerr(EC_F_PKEY_EC_CTRL, EC_R_INVALID_DIGEST_TYPE);
            return 0;
        }
        dctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = dctx->md;
        return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
        /* Default behaviour is OK */
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;

    default:
        return -2;

    }
}

static int pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx,
                            const char *type, const char *value)
{
    printf("dddddddddddd pkey_ec_ctrl_str\n");
    if (strcmp(type, "ec_paramgen_curve") == 0) {
        int nid;
        nid = EC_curve_nist2nid(value);
        if (nid == NID_undef)
            nid = OBJ_sn2nid(value);
        if (nid == NID_undef)
            nid = OBJ_ln2nid(value);
        if (nid == NID_undef) {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_CURVE);
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    } else if (strcmp(type, "ec_param_enc") == 0) {
        int param_enc;
        if (strcmp(value, "explicit") == 0)
            param_enc = 0;
        else if (strcmp(value, "named_curve") == 0)
            param_enc = OPENSSL_EC_NAMED_CURVE;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    } else if (strcmp(type, "ecdh_kdf_md") == 0) {
        const EVP_MD *md;
        if ((md = EVP_get_digestbyname(value)) == NULL) {
            ECerr(EC_F_PKEY_EC_CTRL_STR, EC_R_INVALID_DIGEST);
            return 0;
        }
        return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    } else if (strcmp(type, "ecdh_cofactor_mode") == 0) {
        int co_mode;
        co_mode = atoi(value);
        return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
    }

    return -2;
}

static int pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    printf("dddddddddddd pkey_ec_paramgen\n");
    EC_KEY *ec = NULL;
    EC_PKEY_CTX *dctx = ctx->data;
    int ret;

    if (dctx->gen_group == NULL) {
        ECerr(EC_F_PKEY_EC_PARAMGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (ec == NULL)
        return 0;
    if (!(ret = EC_KEY_set_group(ec, dctx->gen_group))
        || !ossl_assert(ret = EVP_PKEY_assign_EC_KEY(pkey, ec)))
        EC_KEY_free(ec);
    return ret;
}

static int pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    printf("dddddddddddd pkey_ec_keygen\n");
    EC_KEY *ec = NULL;
    EC_PKEY_CTX *dctx = ctx->data;
    int ret;

    if (ctx->pkey == NULL && dctx->gen_group == NULL) {
        ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_NO_PARAMETERS_SET);
        return 0;
    }
    ec = EC_KEY_new();
    if (ec == NULL)
        return 0;
    if (!ossl_assert(EVP_PKEY_assign_EC_KEY(pkey, ec))) {
        EC_KEY_free(ec);
        return 0;
    }
    /* Note: if error is returned, we count on caller to free pkey->pkey.ec */
    if (ctx->pkey != NULL)
        ret = EVP_PKEY_copy_parameters(pkey, ctx->pkey);
    else
        ret = EC_KEY_set_group(ec, dctx->gen_group);

    return ret ? EC_KEY_generate_key(ec) : 0;
}

const EVP_PKEY_METHOD ec_pkey_meth = {
    EVP_PKEY_EC,
    0,
    pkey_ec_init,
    pkey_ec_copy,
    pkey_ec_cleanup,

    0,
    pkey_ec_paramgen,

    0,
    pkey_ec_keygen,

    0,
    pkey_ec_sign,

    0,
    pkey_ec_verify,

    0, 0,

    0, 0, 0, 0,

    0,
    0,

    0,
    0,

    0,
#ifndef OPENSSL_NO_EC
    pkey_ec_kdf_derive,
#else
    0,
#endif
    pkey_ec_ctrl,
    pkey_ec_ctrl_str
};






typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Duplicate key if custom cofactor needed */
    EC_KEY *co_key;
    /* Cofactor mode */
    signed char cofactor_mode;
    /* KDF (if any) to use for ECDH */
    char kdf_type;
    /* Message digest to use for key derivation */
    const EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
    int ec_scheme;
    char *signer_id;
    unsigned char *signer_zid;
    int ec_encrypt_param;
} GMold_SM2_PKEY_CTX;

static int GMold_pkey_sm2_init(EVP_PKEY_CTX *ctx)
{
    GMold_SM2_PKEY_CTX *dctx;

    dctx = OPENSSL_zalloc(sizeof(*dctx));
    if (dctx == NULL)
        return 0;

    dctx->cofactor_mode = -1;
    dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
    dctx->ec_scheme = GMold_NID_secg_scheme;
    dctx->signer_id = NULL;
    dctx->signer_zid = NULL;
    dctx->ec_encrypt_param = GMold_NID_undef;
    ctx->data = dctx;
    return 1;
}

static int GMold_pkey_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    GMold_SM2_PKEY_CTX *dctx, *sctx;
    if (!GMold_pkey_sm2_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->gen_group) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (!dctx->gen_group)
            return 0;
    }
    dctx->md = sctx->md;

    if (sctx->co_key) {
        dctx->co_key = EC_KEY_dup(sctx->co_key);
        if (!dctx->co_key)
            return 0;
    }
    dctx->kdf_type = sctx->kdf_type;
    dctx->kdf_md = sctx->kdf_md;
    dctx->kdf_outlen = sctx->kdf_outlen;
    if (sctx->kdf_ukm) {
        dctx->kdf_ukm = OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
        if (!dctx->kdf_ukm)
            return 0;
    } else
        dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = sctx->kdf_ukmlen;
    dctx->ec_scheme = sctx->ec_scheme;
    if (sctx->signer_id) {
        dctx->signer_id = OPENSSL_strdup(sctx->signer_id);
        if (!dctx->signer_id)
            return 0;
    }
    dctx->signer_zid = NULL;
    dctx->ec_encrypt_param = sctx->ec_encrypt_param;
    return 1;
}

static void GMold_pkey_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    if (dctx) {
        EC_GROUP_free(dctx->gen_group);
        EC_KEY_free(dctx->co_key);
        OPENSSL_free(dctx->kdf_ukm);
        OPENSSL_free(dctx->signer_id);
        OPENSSL_free(dctx->signer_zid);
        OPENSSL_free(dctx);
    }
}
static int GMold_pkey_sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;

    if (!sig) {
        *siglen = GMold_ECDSA_size(ec);
        return 1;
    } else if (*siglen < (size_t)GMold_ECDSA_size(ec)) {
        return 0;
    }

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = GMold_NID_sha1;

    if (dctx->ec_scheme == GMold_NID_sm_scheme)
        ret = GMold_SM2_sign(GMold_NID_undef, tbs, tbslen, sig, &sltmp, ec);
    else
        ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

int GMold_SM2_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char *sig, int siglen, EC_KEY *ec_key);
static int GMold_pkey_sm2_verify(EVP_PKEY_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec = ctx->pkey->pkey.ec;

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = GMold_NID_sha1;

    if (dctx->ec_scheme == GMold_NID_sm_scheme)
        ret = GMold_SM2_verify(GMold_NID_undef, tbs, tbslen, sig, siglen, ec);
    else
        ret = GMold_ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);

    return ret;
}

static int GMold_pkey_sm2_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    int ret = 0;
    if (dctx->gen_group == NULL) {
        return 0;
    }
    ec = EC_KEY_new();
    if (ec == NULL)
        return 0;
    ret = EC_KEY_set_group(ec, dctx->gen_group);
    if (ret)
        EVP_PKEY_assign_EC_KEY(pkey, ec);
    else
        EC_KEY_free(ec);
    return ret;
}

static int GMold_pkey_sm2_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    if (ctx->pkey == NULL && dctx->gen_group == NULL) {
        return 0;
    }
    ec = EC_KEY_new();
    if (!ec)
        return 0;
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    if (ctx->pkey) {
        /* Note: if error return, pkey is freed by parent routine */
        if (!EVP_PKEY_copy_parameters(pkey, ctx->pkey))
            return 0;
    } else {
        if (!EC_KEY_set_group(ec, dctx->gen_group))
            return 0;
    }
    return EC_KEY_generate_key(pkey->pkey.ec);
}

int GMold_SM2_encrypt(const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);

static int GMold_pkey_sm2_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec_key = ctx->pkey->pkey.ec;

    switch (dctx->ec_scheme) {
    case GMold_NID_sm_scheme:
        printf("ddd pkey_ec_encrypt 111 dctx->ec_encrypt_param:%d\n",dctx->ec_encrypt_param);
        if (!GMold_SM2_encrypt(in, inlen, out, outlen, ec_key)) {
            return 0;
        }
        break;
    case GMold_NID_secg_scheme:
        printf("ddd pkey_ec_encrypt 222 dctx->ec_encrypt_param:%d\n",dctx->ec_encrypt_param);
        // if (!ECIES_encrypt(dctx->ec_encrypt_param, in, inlen, out, outlen, ec_key)) {
        //     return 0;
        // }
        break;
    default:
        return 0;
    }

    return 1;
}

int GMold_SM2_decrypt(const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
static int GMold_pkey_sm2_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    EC_KEY *ec_key = ctx->pkey->pkey.ec;

    switch (dctx->ec_scheme) {
    case  GMold_NID_sm_scheme:
        printf("ddd pkey_ec_decrypt 111 dctx->ec_encrypt_param:%d\n",dctx->ec_encrypt_param);
        if (!GMold_SM2_decrypt(in, inlen, out, outlen, ec_key)) {
            return 0;
        }
        break;
    case GMold_NID_secg_scheme:
        printf("ddd pkey_ec_decrypt 111 dctx->ec_encrypt_param:%d\n",dctx->ec_encrypt_param);
        // if (!ECIES_decrypt(dctx->ec_encrypt_param, in, inlen, out, outlen, ec_key)) {
        //     return 0;
        // }
        break;

    default:
        return 0;
    }

    return 1;
}

static int GMold_pkey_sm2_kdf_derive(EVP_PKEY_CTX *ctx,
                              unsigned char *key, size_t *keylen)
{
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    unsigned char *ktmp = NULL;
    size_t ktmplen;
    int rv = 0;
    if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE)
        return pkey_ec_derive(ctx, key, keylen);
    if (!key) {
        *keylen = dctx->kdf_outlen;
        return 1;
    }
    if (*keylen != dctx->kdf_outlen)
        return 0;
    if (!pkey_ec_derive(ctx, NULL, &ktmplen))
        return 0;
    ktmp = OPENSSL_malloc(ktmplen);
    if (ktmp == NULL)
        return 0;
    if (!pkey_ec_derive(ctx, ktmp, &ktmplen))
        goto err;
    /* Do KDF stuff */
    if (!ECDH_KDF_X9_62(key, *keylen, ktmp, ktmplen,
                        dctx->kdf_ukm, dctx->kdf_ukmlen, dctx->kdf_md))
        goto err;
    rv = 1;

 err:
    OPENSSL_clear_free(ktmp, ktmplen);
    return rv;
}

static int GMold_pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    GMold_SM2_PKEY_CTX *dctx = ctx->data;
    EC_GROUP *group;
    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            return 0;
        }
        EC_GROUP_free(dctx->gen_group);
        dctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (!dctx->gen_group) {
            return 0;
        }
        EC_GROUP_set_asn1_flag(dctx->gen_group, p1);
        return 1;

    case EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
        if (p1 == -2) {
            if (dctx->cofactor_mode != -1)
                return dctx->cofactor_mode;
            else {
                EC_KEY *ec_key = ctx->pkey->pkey.ec;
                return EC_KEY_get_flags(ec_key) & EC_FLAG_COFACTOR_ECDH ? 1 :
                    0;
            }
        } else if (p1 < -1 || p1 > 1)
            return -2;
        dctx->cofactor_mode = p1;
        if (p1 != -1) {
            EC_KEY *ec_key = ctx->pkey->pkey.ec;
            if (!ec_key->group)
                return -2;
            /* If cofactor is 1 cofactor mode does nothing */
            if (BN_is_one(ec_key->group->cofactor))
                return 1;
            if (!dctx->co_key) {
                dctx->co_key = EC_KEY_dup(ec_key);
                if (!dctx->co_key)
                    return 0;
            }
            if (p1)
                EC_KEY_set_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
            else
                EC_KEY_clear_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
        } else {
            EC_KEY_free(dctx->co_key);
            dctx->co_key = NULL;
        }
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_TYPE:
        if (p1 == -2)
            return dctx->kdf_type;
        if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_62)
            return -2;
        dctx->kdf_type = p1;
        return 1;

    case EVP_PKEY_CTRL_EC_SCHEME:
        if (p1 == -2) {
            return dctx->ec_scheme;
        }
        if (p1 != GMold_NID_secg_scheme && p1 != GMold_NID_sm_scheme) { //NID_sm_scheme
            return 0;
        }
        dctx->ec_scheme = p1;
        return 1;

    case EVP_PKEY_CTRL_SIGNER_ID:
        if (!p2 || !strlen((char *)p2) || strlen((char *)p2) > SM2_MAX_ID_LENGTH) {
            return 0;
        } else {
            char *id = NULL;
            if (!(id = OPENSSL_strdup((char *)p2))) {
                return 0;
            }
            if (dctx->signer_id)
                OPENSSL_free(dctx->signer_id);
            dctx->signer_id = id;
            if (dctx->ec_scheme == GMold_NID_sm_scheme) {
                EC_KEY *ec_key = ctx->pkey->pkey.ec;
                unsigned char zid[SM3_DIGEST_LENGTH];
                size_t zidlen = SM3_DIGEST_LENGTH;
                if (!GMold_SM2_compute_id_digest(GMold_EVP_sm3(), dctx->signer_id,
                    strlen(dctx->signer_id), zid, &zidlen, ec_key)) {
                    return 0;
                }
                if (!dctx->signer_zid) {
                    if (!(dctx->signer_zid = OPENSSL_malloc(zidlen))) {
                        return 0;
                    }
                }
                memcpy(dctx->signer_zid, zid, zidlen);
            }
        }
        return 1;

    case EVP_PKEY_CTRL_GET_SIGNER_ID:
        *(const char **)p2 = dctx->signer_id;
        return 1;

    case EVP_PKEY_CTRL_GET_SIGNER_ZID:
        if (dctx->ec_scheme != GMold_NID_sm_scheme) {
            *(const unsigned char **)p2 = NULL;
            return -2;
        }
        if (!dctx->signer_zid) {
            EC_KEY *ec_key = ctx->pkey->pkey.ec;
            unsigned char *zid;
            size_t zidlen = SM3_DIGEST_LENGTH;
            if (!(zid = OPENSSL_malloc(zidlen))) {
                return 0;
            }
            if (!GMold_SM2_compute_id_digest(GMold_EVP_sm3(), SM2_DEFAULT_ID,
                SM2_DEFAULT_ID_LENGTH, zid, &zidlen, ec_key)) {
                OPENSSL_free(zid);
                return 0;
            }
            dctx->signer_zid = zid;
            fprintf(stderr, "[SM2_DEBUG] EVP_PKEY_CTX_get_signer_zid() "
                "init zid with default id\n");
        }
        *(const unsigned char **)p2 = dctx->signer_zid;
        return 1;

    case EVP_PKEY_CTRL_EC_ENCRYPT_PARAM:
        if (p1 == -2) {
            return dctx->ec_encrypt_param;
        }
        dctx->ec_encrypt_param = p1;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_MD:
        dctx->kdf_md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_MD:
        *(const EVP_MD **)p2 = dctx->kdf_md;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
        if (p1 <= 0)
            return -2;
        dctx->kdf_outlen = (size_t)p1;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
        *(int *)p2 = dctx->kdf_outlen;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_UKM:
        OPENSSL_free(dctx->kdf_ukm);
        dctx->kdf_ukm = p2;
        if (p2)
            dctx->kdf_ukmlen = p1;
        else
            dctx->kdf_ukmlen = 0;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_UKM:
        *(unsigned char **)p2 = dctx->kdf_ukm;
        return dctx->kdf_ukmlen;

    case EVP_PKEY_CTRL_MD:
        if (EVP_MD_type((const EVP_MD *)p2) != GMold_NID_sha1 &&
            EVP_MD_type((const EVP_MD *)p2) != GMold_NID_sm3 &&
            EVP_MD_type((const EVP_MD *)p2) != GMold_NID_ecdsa_with_SHA1 &&
            EVP_MD_type((const EVP_MD *)p2) != GMold_NID_sha224 &&
            EVP_MD_type((const EVP_MD *)p2) != GMold_NID_sha256 &&
            EVP_MD_type((const EVP_MD *)p2) != GMold_NID_sha384 &&
            EVP_MD_type((const EVP_MD *)p2) != GMold_NID_sha512) {
            return 0;
        }
        dctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = dctx->md;
        return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
        /* Default behaviour is OK */
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;

    default:
        return -2;

    }
}

static int GMold_pkey_sm2_ctrl_str(EVP_PKEY_CTX *ctx,
                            const char *type, const char *value)
{
    if (strcmp(type, "ec_paramgen_curve") == 0) {
        int nid;
        nid = EC_curve_nist2nid(value);
        if (nid == GMold_NID_undef)
            nid = OBJ_sn2nid(value);
        if (nid == GMold_NID_undef)
            nid = OBJ_ln2nid(value);
        if (nid == GMold_NID_undef) {
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    } else if (!strcmp(type, "ec_scheme")) {
        int scheme;
        if (!strcmp(value, "secg"))
            scheme = GMold_NID_secg_scheme;
        else if (!strcmp(value, "sm2"))
            scheme = GMold_NID_sm_scheme;
        else
            return -2;
        return GMold_EVP_PKEY_CTX_ctrl(ctx, GMold_EVP_PKEY_EC, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX| \
		EVP_PKEY_OP_ENCRYPT|EVP_PKEY_OP_DECRYPT| \
		EVP_PKEY_OP_DERIVE, \
		EVP_PKEY_CTRL_EC_SCHEME, scheme, NULL);
    } else if (!strcmp(type, "signer_id")) {
        return GMold_EVP_PKEY_CTX_ctrl(ctx, GMold_EVP_PKEY_EC, \
		EVP_PKEY_OP_SIGN|EVP_PKEY_OP_SIGNCTX| \
		EVP_PKEY_OP_VERIFY|EVP_PKEY_OP_VERIFYCTX| \
		EVP_PKEY_OP_DERIVE, \
		EVP_PKEY_CTRL_SIGNER_ID, 0, (void *)value);
    } else if (!strcmp(type, "ec_encrypt_param")) {
        int encrypt_param;
        if (!(encrypt_param = OBJ_txt2nid(value))) {
            return 0;
        }
        return GMold_EVP_PKEY_CTX_ctrl(ctx, GMold_EVP_PKEY_EC, \
		EVP_PKEY_OP_ENCRYPT|EVP_PKEY_OP_DECRYPT, \
		EVP_PKEY_CTRL_EC_ENCRYPT_PARAM, encrypt_param, NULL);
    } else if (strcmp(type, "ec_param_enc") == 0) {
        int param_enc;
        if (strcmp(value, "explicit") == 0)
            param_enc = 0;
        else if (strcmp(value, "named_curve") == 0)
            param_enc = OPENSSL_EC_NAMED_CURVE;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    } else if (strcmp(type, "ecdh_kdf_md") == 0) {
        const EVP_MD *md;
        if ((md = EVP_get_digestbyname(value)) == NULL) {
            return 0;
        }
        return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    } else if (strcmp(type, "ecdh_cofactor_mode") == 0) {
        int co_mode;
        co_mode = atoi(value);
        return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
    }

    return -2;
}


const EVP_PKEY_METHOD GMold_sm2_pkey_meth = {
    GMold_EVP_PKEY_EC,
    0,
    GMold_pkey_sm2_init,
    GMold_pkey_sm2_copy,
    GMold_pkey_sm2_cleanup,

    0,
    GMold_pkey_sm2_paramgen,

    0,
    GMold_pkey_sm2_keygen,

    0,
    GMold_pkey_sm2_sign,

    0,
    GMold_pkey_sm2_verify,

    0, 0,

    0, 0, 0, 0,

    0,
    GMold_pkey_sm2_encrypt,

    0,
    GMold_pkey_sm2_decrypt,

    0,
    GMold_pkey_sm2_kdf_derive,

    GMold_pkey_sm2_ctrl,
    GMold_pkey_sm2_ctrl_str
};
