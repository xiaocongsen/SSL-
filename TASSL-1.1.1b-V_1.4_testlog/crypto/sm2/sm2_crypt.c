/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/sm2.h"
#include "internal/sm2err.h"
#include "internal/ec_int.h" /* ecdh_KDF_X9_63() */
#include "internal/o_str.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <string.h>

void GMold_RAND_seed(const void *buf, int num);

typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

ASN1_SEQUENCE(SM2_Ciphertext) = {
    ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)

static size_t ec_field_size(const EC_GROUP *group)
{
        printf("dddddddddd ec_field_size \n");
    /* Is there some simpler way to do this? */
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    size_t field_size = 0;

    if (p == NULL || a == NULL || b == NULL)
       goto done;

    if (!EC_GROUP_get_curve(group, p, a, b, NULL))
        goto done;
    field_size = (BN_num_bits(p) + 7) / 8;

 done:
    BN_free(p);
    BN_free(a);
    BN_free(b);

    return field_size;
}

int sm2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                       size_t *pt_size)
{
        printf("dddddddddd sm2_plaintext_size \n");
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t overhead;

    if (md_size < 0) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_DIGEST);
        return 0;
    }
    if (field_size == 0) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_FIELD);
        return 0;
    }

    overhead = 10 + 2 * field_size + (size_t)md_size;
    if (msg_len <= overhead) {
        SM2err(SM2_F_SM2_PLAINTEXT_SIZE, SM2_R_INVALID_ENCODING);
        return 0;
    }

    *pt_size = msg_len - overhead;
    return 1;
}

int sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size)
{
    printf("dddddddddd sm2_ciphertext_size \n");
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_size(digest);
    size_t sz;

    if (field_size == 0 || md_size < 0)
        return 0;

    /* Integer and string are simple type; set constructed = 0, means primitive and definite length encoding. */
    sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
         + ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
         + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
    /* Sequence is structured type; set constructed = 1, means constructed and definite length encoding. */
    *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

    return 1;
}

int sm2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len, uint8_t *ciphertext_buf, size_t *ciphertext_len)
{
        printf("dddddddddd sm2_encrypt \n");
    int rc = 0, ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    struct SM2_Ciphertext_st ctext_struct;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *C3 = NULL;
    size_t field_size;
    const int C3_size = EVP_MD_size(digest);

    /* NULL these before any "goto done" */
    ctext_struct.C2 = NULL;
    ctext_struct.C3 = NULL;

    if (hash == NULL || C3_size <= 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    field_size = ec_field_size(group);
    if (field_size == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || kP == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_BN_LIB);
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    C3 = OPENSSL_zalloc(C3_size);

    if (x2y2 == NULL || C3 == NULL) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memset(ciphertext_buf, 0, *ciphertext_len);

    if (!BN_priv_rand_range(k, order)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                        digest)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    if (EVP_DigestInit(hash, digest) == 0
            || EVP_DigestUpdate(hash, x2y2, field_size) == 0
            || EVP_DigestUpdate(hash, msg, msg_len) == 0
            || EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0
            || EVP_DigestFinal(hash, C3, NULL) == 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;
    ctext_struct.C3 = ASN1_OCTET_STRING_new();
    ctext_struct.C2 = ASN1_OCTET_STRING_new();

    if (ctext_struct.C3 == NULL || ctext_struct.C2 == NULL) {
       SM2err(SM2_F_SM2_ENCRYPT, ERR_R_MALLOC_FAILURE);
       goto done;
    }
    if (!ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size)
            || !ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);
    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        SM2err(SM2_F_SM2_ENCRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    rc = 1;

 done:
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(C3);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}

int sm2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len)
{
    printf("dddddddddd sm2_decrypt \n");
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct SM2_Ciphertext_st *sm2_ctext = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const int hash_size = EVP_MD_size(digest);
    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;

    if (field_size == 0 || hash_size <= 0)
       goto done;

    memset(ptext_buf, 0xFF, *ptext_len);

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

    if (sm2_ctext == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_ASN1_ERROR);
        goto done;
    }

    if (sm2_ctext->C3->length != hash_size) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_ENCODING);
        goto done;
    }

    C2 = sm2_ctext->C2->data;
    C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;

    ctx = BN_CTX_new();
    if (ctx == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_BN_LIB);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    computed_C3 = OPENSSL_zalloc(hash_size);

    if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x,
                                         sm2_ctext->C1y, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key),
                             ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ecdh_KDF_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                               digest)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, x2y2, field_size)
            || !EVP_DigestUpdate(hash, ptext_buf, msg_len)
            || !EVP_DigestUpdate(hash, x2y2 + field_size, field_size)
            || !EVP_DigestFinal(hash, computed_C3, NULL)) {
        SM2err(SM2_F_SM2_DECRYPT, ERR_R_EVP_LIB);
        goto done;
    }

    if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
        SM2err(SM2_F_SM2_DECRYPT, SM2_R_INVALID_DIGEST);
        goto done;
    }

    rc = 1;
    *ptext_len = msg_len;

 done:
    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(computed_C3);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    SM2_Ciphertext_free(sm2_ctext);
    EVP_MD_CTX_free(hash);

    return rc;
}

static void *GMold_x963_kdf(const EVP_MD *md, const void *in, size_t inlen,
	void *out, size_t *outlen)
{
	void *ret = NULL;
	EVP_MD_CTX *ctx = NULL;
	uint32_t counter = 1;
	uint32_t counter_be;
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	unsigned char *pout = out;
	size_t rlen = *outlen;
	size_t len;

	if (!(ctx = EVP_MD_CTX_new())) {
		goto end;
	}

	while (rlen > 0) {
		counter_be = (((counter)>>24) | (((counter)>>8)&0xff00) | (((counter)<<8)&0xff0000) | ((counter)<<24));
		counter++;

		if (!GMold_EVP_DigestInit(ctx, md)) {
			goto end;
		}
		if (!GMold_EVP_DigestUpdate(ctx, in, inlen)) {
			goto end;
		}
		if (!GMold_EVP_DigestUpdate(ctx, &counter_be, sizeof(counter_be))) {
			goto end;
		}
		if (!EVP_DigestFinal(ctx, dgst, &dgstlen)) {
			goto end;
		}

		len = dgstlen <= rlen ? dgstlen : rlen;
		memcpy(pout, dgst, len);
		rlen -= len;
		pout += len;
	}

	ret = out;
end:
	EVP_MD_CTX_free(ctx);
	return ret;
}

static void *GMold_x963_sm3kdf(const void *in, size_t inlen, void *out, size_t *outlen) 
{ 
    return GMold_x963_kdf(GMold_EVP_sm3(), in, inlen, out, outlen); 
}

int GMold_ASN1_OCTET_STRING_is_zero(const ASN1_OCTET_STRING *a)
{
    int i;
    for (i = 0; i < a->length; i++) {
        if (a->data[i] != 0) {
            return 0;
        }
    }
    return 1;
}

static const ASN1_TEMPLATE GMold_SM2CiphertextValue_seq_tt[] = {
        { (0), (0), ((size_t)&(((SM2CiphertextValue*)0)->xCoordinate)), "xCoordinate", (&(GMold_BIGNUM_it)) },
        { (0), (0), ((size_t)&(((SM2CiphertextValue*)0)->yCoordinate)), "yCoordinate", (&(GMold_BIGNUM_it)) },
        { (0), (0), ((size_t)&(((SM2CiphertextValue*)0)->hash)), "hash", (&(GMold_ASN1_OCTET_STRING_it)) },
        { (0), (0), ((size_t)&(((SM2CiphertextValue*)0)->ciphertext)), "ciphertext", (&(GMold_ASN1_OCTET_STRING_it)) },
};

const ASN1_ITEM GMold_SM2CiphertextValue_it = {
    ASN1_ITYPE_SEQUENCE, V_ASN1_SEQUENCE, GMold_SM2CiphertextValue_seq_tt,
    sizeof(GMold_SM2CiphertextValue_seq_tt) / sizeof(ASN1_TEMPLATE),
    NULL, sizeof(SM2CiphertextValue), "SM2CiphertextValue"
};

SM2CiphertextValue *GMold_d2i_SM2CiphertextValue(SM2CiphertextValue **a, const unsigned char **in, long len)
{ 
    return (SM2CiphertextValue *)GMold_ASN1_item_d2i((ASN1_VALUE **)a, in, len, &(GMold_SM2CiphertextValue_it));
} 
int GMold_i2d_SM2CiphertextValue(SM2CiphertextValue *a, unsigned char **out)
{ 
    return GMold_ASN1_item_i2d((ASN1_VALUE *)a, out, &(GMold_SM2CiphertextValue_it));
} 
SM2CiphertextValue *GMold_SM2CiphertextValue_new(void)
{ 
    return (SM2CiphertextValue *)ASN1_item_new(&(GMold_SM2CiphertextValue_it));
} 
void GMold_SM2CiphertextValue_free(SM2CiphertextValue *a)
{ 
    ASN1_item_free((ASN1_VALUE *)a, &(GMold_SM2CiphertextValue_it));
}
SM2CiphertextValue * GMold_SM2CiphertextValue_dup(SM2CiphertextValue *x)
{ 
    return ASN1_item_dup(&(GMold_SM2CiphertextValue_it), x);
}

int GMold_SM2CiphertextValue_size(const EC_GROUP *group, int inlen)
{
	return 1024;
}

int GMold_SM2_get_public_key_data(EC_KEY *ec_key, unsigned char *out, size_t *outlen)
{
	int ret = 0;
	const EC_GROUP *group;
	BN_CTX *bn_ctx = NULL;
	BIGNUM *p;
	BIGNUM *x;
	BIGNUM *y;
	int nbytes;
	size_t len;

	if (!ec_key || !outlen || !(group = EC_KEY_get0_group(ec_key))) {
		return 0;
	}

	/* degree is the bit length of field element, not the order of subgroup */
        nbytes = (GMold_EC_GROUP_get_degree(group) + 7)/8;
	len = nbytes * 6;

	if (!out) {
		*outlen = len;
		return 1;
	}
	if (*outlen < len) {
		return 0;
	}

	if (!(bn_ctx = BN_CTX_new())) {
		goto  end;
	}

	BN_CTX_start(bn_ctx);
        p = GMold_BN_CTX_get(bn_ctx);
        x = GMold_BN_CTX_get(bn_ctx);
        y = GMold_BN_CTX_get(bn_ctx);
	if (!y) {
		goto end;
	}

	memset(out, 0, len);

	/* get curve coefficients */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_GROUP_get_curve_GFp(group, p, x, y, bn_ctx)) {
			goto end;
		}
	} else {
		if (!EC_GROUP_get_curve_GF2m(group, p, x, y, bn_ctx)) {
			goto end;
		}
	}

	/* when coeffiient a is zero, BN_bn2bin/BN_num_bytes return 0 */
        GMold_BN_bn2bin(x, out + nbytes - GMold_BN_num_bytes(x));
	out += nbytes;

        if (!GMold_BN_bn2bin(y, out + nbytes - GMold_BN_num_bytes(y))) {
		goto end;
	}
	out += nbytes;

	/* get curve generator coordinates */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
                if (!GMold_EC_POINT_get_affine_coordinates_GFp(group,
			EC_GROUP_get0_generator(group), x, y, bn_ctx)) {
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group,
			EC_GROUP_get0_generator(group), x, y, bn_ctx)) {
			goto end;
		}
	}

        if (!GMold_BN_bn2bin(x, out + nbytes - GMold_BN_num_bytes(x))) {
		goto end;
	}
	out += nbytes;

        if (!GMold_BN_bn2bin(y, out + nbytes - GMold_BN_num_bytes(y))) {
		goto end;
	}
	out += nbytes;

	/* get pub_key coorindates */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
                if (!GMold_EC_POINT_get_affine_coordinates_GFp(group,
			EC_KEY_get0_public_key(ec_key), x, y, bn_ctx)) {
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group,
			EC_KEY_get0_public_key(ec_key), x, y, bn_ctx)) {
			goto end;
		}
	}

        if (!GMold_BN_bn2bin(x, out + nbytes - GMold_BN_num_bytes(x))) {
		goto end;
	}
	out += nbytes;

        if (!GMold_BN_bn2bin(y, out + nbytes - GMold_BN_num_bytes(y))) {
		goto end;
	}

	*outlen = len;
	ret = 1;

end:
	if (bn_ctx) {
		BN_CTX_end(bn_ctx);
	}
	BN_CTX_free(bn_ctx);
	return ret;
}

int GMold_SM2_compute_id_digest(const EVP_MD *md, const char *id, size_t idlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char idbits[2];
	unsigned char pkdata[SM2_MAX_PKEY_DATA_LENGTH];
	unsigned int len;
	size_t size;

	if (!md || !id || idlen <= 0 || !outlen || !ec_key) {
		return 0;
	}

	if (EVP_MD_size(md) != 32) {
		return 0;
	}

	if (strlen(id) != idlen) {
		return 0;
	}
	if (idlen > SM2_MAX_ID_LENGTH || idlen <= 0) {
		return 0;
	}

	if (!out) {
		*outlen = EVP_MD_size(md);
		return 1;
	}
	if (*outlen < EVP_MD_size(md)) {
		return 0;
	}


	/* get public key data from ec_key */
	size = sizeof(pkdata);
	if (!GMold_SM2_get_public_key_data(ec_key, pkdata, &size)) {
		goto end;
	}

	/* 2-byte id length in bits */
	idbits[0] = ((idlen * 8) >> 8) % 256;
	idbits[1] = (idlen * 8) % 256;

	len = EVP_MD_size(md);

	if (!(md_ctx = EVP_MD_CTX_new())
		|| !GMold_EVP_DigestInit_ex(md_ctx, md, NULL)
		|| !GMold_EVP_DigestUpdate(md_ctx, idbits, sizeof(idbits))
		|| !GMold_EVP_DigestUpdate(md_ctx, id, idlen)
		|| !GMold_EVP_DigestUpdate(md_ctx, pkdata, size)
		|| !EVP_DigestFinal_ex(md_ctx, out, &len)) {
		goto end;
	}

	*outlen = len;
	ret = 1;

end:
	EVP_MD_CTX_free(md_ctx);
        return ret;
}



SM2CiphertextValue *GMold_SM2_do_encrypt(const EVP_MD *md,
	const unsigned char *in, size_t inlen, EC_KEY *ec_key)
{
	SM2CiphertextValue *ret = NULL;
	SM2CiphertextValue *cv = NULL;
	const EC_GROUP *group;
	const EC_POINT *pub_key;
	EC_POINT *ephem_point = NULL;
	EC_POINT *share_point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BIGNUM *k = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;

	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	int nbytes;
	size_t len;
	size_t i;
	unsigned int hashlen;

	/* check arguments */
	if (!md || !in || !ec_key) {
		return 0;
	}

	if (inlen < 0 || inlen > 1024) {
		return 0;
	}

	if (!(group = EC_KEY_get0_group(ec_key))
		|| !(pub_key = EC_KEY_get0_public_key(ec_key))) {
		return 0;
	}

	/* malloc */
        if (!(cv = GMold_SM2CiphertextValue_new())
		|| !(ephem_point = EC_POINT_new(group))
		|| !(share_point = EC_POINT_new(group))
		|| !(n = BN_new())
		|| !(h = BN_new())
		|| !(k = BN_new())
		|| !(bn_ctx = BN_CTX_new())
		|| !(md_ctx = EVP_MD_CTX_new())) {
		goto end;
	}

	if (!ASN1_OCTET_STRING_set(cv->ciphertext, NULL, (int)inlen)
		|| !ASN1_OCTET_STRING_set(cv->hash, NULL, EVP_MD_size(md))) {
		goto end;
	}

	/* init ec domain parameters */
        if (!GMold_EC_GROUP_get_order(group, n, bn_ctx)) {
		goto end;
	}

        if (!GMold_EC_GROUP_get_cofactor(group, h, bn_ctx)) {
		goto end;
	}

	nbytes = (GMold_EC_GROUP_get_degree(group) + 7) / 8;

	/* check [h]P_B != O */
        if (!GMold_EC_POINT_mul(group, share_point, NULL, pub_key, h, bn_ctx)) {
		goto end;
	}

	if (EC_POINT_is_at_infinity(group, share_point)) {
		goto end;
	}

	do
	{
		size_t size;

		/* rand k in [1, n-1] */
		do {
                        GMold_BN_rand_range(k, n);
		} while (BN_is_zero(k));

		/* compute ephem_point [k]G = (x1, y1) */
                if (!GMold_EC_POINT_mul(group, ephem_point, k, NULL, NULL, bn_ctx)) {
			goto end;
		}

		/* compute ECDH share_point [k]P_B = (x2, y2) */
                if (!GMold_EC_POINT_mul(group, share_point, NULL, pub_key, k, bn_ctx)) {
			goto end;
		}

		/* compute t = KDF(x2 || y2, klen) */
                if (!(len = GMold_EC_POINT_point2oct(group, share_point,
			POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
			goto end;
		}

		size = cv->ciphertext->length;
		GMold_x963_sm3kdf(buf + 1, len - 1, cv->ciphertext->data, &size);
		if (size != inlen) {
			goto end;
		}

		/* ASN1_OCTET_STRING_is_zero in asn1.h and a_octet.c */
	} while (GMold_ASN1_OCTET_STRING_is_zero(cv->ciphertext));

	/* set x/yCoordinates as (x1, y1) */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
                if (!GMold_EC_POINT_get_affine_coordinates_GFp(group, ephem_point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			goto end;
		}
	} else {
		if (!EC_POINT_get_affine_coordinates_GF2m(group, ephem_point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			goto end;
		}
	}

	/* ciphertext = t xor in */
	for (i = 0; i < inlen; i++) {
		cv->ciphertext->data[i] ^= in[i];
	}

	/* generate hash = Hash(x2 || M || y2) */
	hashlen = cv->hash->length;
	if (!GMold_EVP_DigestInit_ex(md_ctx, md, NULL)
		|| !GMold_EVP_DigestUpdate(md_ctx, buf + 1, nbytes)
		|| !GMold_EVP_DigestUpdate(md_ctx, in, inlen)
		|| !GMold_EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)
		|| !EVP_DigestFinal_ex(md_ctx, cv->hash->data, &hashlen)) {
		goto end;
	}

	ret = cv;
	cv = NULL;

end:
        GMold_SM2CiphertextValue_free(cv);
	EC_POINT_free(share_point);
	EC_POINT_free(ephem_point);
	BN_free(n);
	BN_free(h);
	BN_clear_free(k);
	BN_CTX_free(bn_ctx);
	EVP_MD_CTX_free(md_ctx);
	return ret;
}


int GMold_SM2_do_decrypt(const EVP_MD *md, const SM2CiphertextValue *cv,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	const EC_GROUP *group;
	const BIGNUM *pri_key;
	EC_POINT *point = NULL;
	EC_POINT *tmp_point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen = sizeof(mac);
	int nbytes, len, i;

	/* check arguments */
	if (!md || !cv || !outlen || !ec_key) {
		return 0;
	}


	if (!cv->xCoordinate || !cv->yCoordinate || !cv->hash || !cv->ciphertext) {
		return 0;
	}

	if (cv->hash->length != EVP_MD_size(md)) {
		return 0;
	}

	if (cv->ciphertext->length < 0
		|| cv->ciphertext->length > 1024) 
    {
		return 0;
	}

	if (!(group = EC_KEY_get0_group(ec_key))
		|| !(pri_key = EC_KEY_get0_private_key(ec_key))) {
		return 0;
	}

	if (!out) {
		*outlen = cv->ciphertext->length;
		return 1;
	}

	/* malloc */
	point = EC_POINT_new(group);
	tmp_point = EC_POINT_new(group);
	n = BN_new();
	h = BN_new();
	bn_ctx = BN_CTX_new();
	md_ctx = EVP_MD_CTX_new();
	if (!point || !n || !h || !bn_ctx || !md_ctx) {
		goto end;
	}

	/* init ec domain parameters */
	if (!EC_GROUP_get_order(group, n, bn_ctx)) {
		goto end;
	}

	if (!EC_GROUP_get_cofactor(group, h, bn_ctx)) {
		goto end;
	}

	nbytes = (EC_GROUP_get_degree(group) + 7) / 8;

	/* get x/yCoordinates as C1 = (x1, y1) */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_set_affine_coordinates_GFp(group, point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			goto end;
		}
	} else {
		if (!EC_POINT_set_affine_coordinates_GF2m(group, point,
			cv->xCoordinate, cv->yCoordinate, bn_ctx)) {
			goto end;
		}
	}

	/* check [h]C1 != O */
	if (!EC_POINT_mul(group, tmp_point, NULL, point, h, bn_ctx)) {
		goto end;
	}

	if (EC_POINT_is_at_infinity(group, tmp_point)) {
		goto end;
	}

	/* compute ECDH [d]C1 = (x2, y2) */
	if (!EC_POINT_mul(group, point, NULL, point, pri_key, bn_ctx)) {
		goto end;
	}

	if (!(len = EC_POINT_point2oct(group, point,
		POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
		goto end;
	}

	/* compute t = KDF(x2 || y2, clen) */
	*outlen = cv->ciphertext->length;
	GMold_x963_sm3kdf(buf + 1, len - 1, out, outlen);


	/* compute M = C2 xor t */
	for (i = 0; i < cv->ciphertext->length; i++) {
		out[i] ^= cv->ciphertext->data[i];
	}

	/* check hash == Hash(x2 || M || y2) */
	if (!GMold_EVP_DigestInit_ex(md_ctx, md, NULL)
		|| !GMold_EVP_DigestUpdate(md_ctx, buf + 1, nbytes)
		|| !GMold_EVP_DigestUpdate(md_ctx, out, *outlen)
		|| !GMold_EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)
		|| !EVP_DigestFinal_ex(md_ctx, mac, &maclen)) {
		goto end;
	}

	if (OPENSSL_memcmp(cv->hash->data, mac, maclen) != 0) {
		goto end;
	}

	ret = 1;
end:
	EC_POINT_free(point);
	EC_POINT_free(tmp_point);
	BN_free(n);
	BN_free(h);
	BN_CTX_free(bn_ctx);
	EVP_MD_CTX_free(md_ctx);
	return ret;
}

int GMold_SM2_encrypt(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	const EVP_MD *md = GMold_EVP_sm3();
	SM2CiphertextValue *cv;

        GMold_RAND_seed(in, inlen);
	if (!(cv = GMold_SM2_do_encrypt(md, in, inlen, ec_key))) {
		*outlen = 0;
		return 0;
	}

        *outlen = GMold_i2d_SM2CiphertextValue(cv, &out);
        GMold_SM2CiphertextValue_free(cv);
	return 1;
}

int GMold_SM2_decrypt(const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen, EC_KEY *ec_key)
{
	int ret = 0;
	const EVP_MD *md = GMold_EVP_sm3();
	const unsigned char *p;
	SM2CiphertextValue *cv = NULL;

	if (!in) {
		*outlen = 0;
		return 0;
	}
	if (inlen <= 0 || inlen > INT_MAX) {
		*outlen = 0;
		return 0;
	}

	/* decode asn.1 and check no data remaining */
	p = in;
        if (!(cv = GMold_d2i_SM2CiphertextValue(NULL, &p, (long)inlen))) {
		return 0;
	}
	if (p != in + inlen) {
		goto end;
	}

	/* return or check output length */
	if (!out) {
		*outlen = ASN1_STRING_length(cv->ciphertext);
		ret = 1;
		goto end;
	}

	/* do decrypt */
	if (!GMold_SM2_do_decrypt(md, cv, out, outlen, ec_key)) {
		goto end;
	}

	ret = 1;

end:
        GMold_SM2CiphertextValue_free(cv);
	return ret;
}

#ifndef OPENSSL_NO_CNSM
/* GM/T003_2012 Defined Key Derive Function */
int kdf_gmt003_2012(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *SharedInfo, size_t SharedInfolen, const EVP_MD *md)
{
    EVP_MD_CTX *mctx = NULL;
    unsigned int counter;
    unsigned char ctr[4];
    size_t mdlen;
    int retval = 0;

    if (!out || !outlen)
    	return retval;
    if (md == NULL) md = EVP_sm3();
    mdlen = EVP_MD_size(md);
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        SM2err(SM2_F_KDF_GMT003_2012, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (counter = 1;; counter++)
    {
        unsigned char dgst[EVP_MAX_MD_SIZE];

        EVP_DigestInit(mctx, md);
        ctr[0] = (unsigned char)((counter >> 24) & 0xFF);
        ctr[1] = (unsigned char)((counter >> 16) & 0xFF);
        ctr[2] = (unsigned char)((counter >> 8) & 0xFF);
        ctr[3] = (unsigned char)(counter & 0xFF);
        if (!EVP_DigestUpdate(mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(mctx, SharedInfo, SharedInfolen))
            goto err;
        if (!EVP_DigestFinal(mctx, dgst, NULL))
            goto err;

        if (outlen > mdlen)
        {
            memcpy(out, dgst, mdlen);
            out += mdlen;
            outlen -= mdlen;
        }
        else
        {
            memcpy(out, dgst, outlen);
            memset(dgst, 0, mdlen);
            break;
        }
    }

    retval = 1;

err:
    EVP_MD_CTX_free(mctx);
    return retval;
}


int SM2Kap_compute_key(void *out, size_t outlen, int server,\
    const char *peer_uid, int peer_uid_len, const char *self_uid, int self_uid_len, \
    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key, const EC_KEY *peer_pub_key, const EC_KEY *self_eckey, \
    const EVP_MD *md)
{
    BN_CTX *ctx = NULL;
    EC_POINT *UorV = NULL;
    const EC_POINT *Rs, *Rp;
    BIGNUM *Xs = NULL, *Xp = NULL, *h = NULL, *t = NULL, *two_power_w = NULL, *order = NULL;
    const BIGNUM *priv_key, *r;
    const EC_GROUP *group;
    int w;
    int ret = -1;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if (outlen > INT_MAX)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!peer_pub_key || !self_eckey)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    
    priv_key = EC_KEY_get0_private_key(self_eckey);
    if (!priv_key)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!peer_ecdhe_key || !self_ecdhe_key)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    Rs = EC_KEY_get0_public_key(self_ecdhe_key);
    Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
    r = EC_KEY_get0_private_key(self_ecdhe_key);

    if (!Rs || !Rp || !r)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ctx = BN_CTX_new();
    Xs = BN_new();
    Xp = BN_new();
    h = BN_new();
    t = BN_new();
    two_power_w = BN_new();
    order = BN_new();

    if (!Xs || !Xp || !h || !t || !two_power_w || !order)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    group = EC_KEY_get0_group(self_eckey);

    /*Second: Caculate -- w*/
    if (!EC_GROUP_get_order(group, order, ctx) || !EC_GROUP_get_cofactor(group, h, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    w = (BN_num_bits(order) + 1) / 2 - 1;
    if (!BN_lshift(two_power_w, BN_value_one(), w))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
    UorV = EC_POINT_new(group);

    if (!UorV)
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*Test peer public key On curve*/
    if (!EC_POINT_is_on_curve(group, Rp, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Get x*/
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
    {
        if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }
#ifndef OPENSSL_NO_EC2M
    else
    {
        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rs, Xs, NULL, ctx))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GF2m(group, Rp, Xp, NULL, ctx))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }
    }
#endif

    /*x mod 2 ^ w*/
    /*Caculate Self x*/
    if (!BN_nnmod(Xs, Xs, two_power_w, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xs, Xs, two_power_w))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Caculate Peer x*/
    if (!BN_nnmod(Xp, Xp, two_power_w, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_add(Xp, Xp, two_power_w))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Forth: Caculate t*/
    if (!BN_mod_mul(t, Xs, r, order, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    if (!BN_mod_add(t, t, priv_key, order, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /*Fifth: Caculate V or U*/
    if (!BN_mul(t, t, h, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    /* [x]R */
    if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /* P + [x]R */
    if (!EC_POINT_add(group, UorV, UorV, EC_KEY_get0_public_key(peer_pub_key), ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /* Detect UorV is in */
    if (EC_POINT_is_at_infinity(group, UorV))
    {
        SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
        goto err;
    }

    /*Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/
    {
        /*
        size_t buflen, len;
        unsigned char *buf = NULL;
        */
        size_t elemet_len, idx;

        elemet_len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
        buflen = elemet_len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
        buf = (unsigned char *)OPENSSL_malloc(buflen + 10);
        if (!buf)
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        memset(buf, 0, buflen + 10);

        /*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
        idx = EC_POINT_point2oct(group, UorV, 4, buf, buflen, ctx);
        if (!idx)
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
            goto err;
        }

        if (!server)
        {
            /*SIDE A*/
            len = buflen - idx;
            if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)self_uid, self_uid_len, self_eckey))
            {
                goto err;
            }
            len = 32;
            idx += len;
        }

        /*Caculate Peer Z*/
        len = buflen - idx;
	  if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)peer_uid, peer_uid_len, peer_pub_key))
            {
                goto err;
            }
        len = 32;
        idx += len;

        if (server)
        {
            /*SIDE B*/
            len = buflen - idx;
	     if (!sm2_compute_z_digest( (unsigned char *)(buf + idx), md, (const uint8_t *)self_uid, self_uid_len, self_eckey))
            {
                goto err;
            }
	     len = 32;
            idx += len;
        }

        len = outlen;
        if (!kdf_gmt003_2012(out, len, (const unsigned char *)(buf + 1), idx - 1, NULL, 0, md))
        {
            SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    ret = outlen;

err:
    if (Xs) BN_free(Xs);
    if (Xp) BN_free(Xp);
    if (h) BN_free(h);
    if (t) BN_free(t);
    if (two_power_w) BN_free(two_power_w);
    if (order) BN_free(order);
    if (UorV) EC_POINT_free(UorV);
    if (buf) OPENSSL_free(buf);
    if (ctx) BN_CTX_free(ctx);

    return ret;
}
#endif
