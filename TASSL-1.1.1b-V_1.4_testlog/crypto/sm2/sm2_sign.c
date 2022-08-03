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
#include "internal/ec_int.h" /* ec_group_do_inverse_ord() */
#include "internal/numbers.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <string.h>
#include "../ec/ec_lcl.h"
void GMold_RAND_seed(const void *buf, int num);

int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    hash = EVP_MD_CTX_new();
    ctx = BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);

    if (yA == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, SM2_R_ID_TOO_LARGE);
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EC_LIB);
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (BN_bn2binpad(a, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(b, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_GROUP_get0_generator(group),
                                                xG, yG, ctx)
            || BN_bn2binpad(xG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yG, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EC_POINT_get_affine_coordinates(group,
                                                EC_KEY_get0_public_key(key),
                                                xA, yA, ctx)
            || BN_bn2binpad(xA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || BN_bn2binpad(yA, buf, p_bytes) < 0
            || !EVP_DigestUpdate(hash, buf, p_bytes)
            || !EVP_DigestFinal(hash, out, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    rc = 1;

 done:
    OPENSSL_free(buf);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return rc;
}

static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
                                    const EC_KEY *key,
                                    const uint8_t *id,
                                    const size_t id_len,
                                    const uint8_t *msg, size_t msg_len)
{
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const int md_size = EVP_MD_size(digest);
    uint8_t *z = NULL;
    BIGNUM *e = NULL;

    if (md_size < 0) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, SM2_R_INVALID_DIGEST);
        goto done;
    }

    z = OPENSSL_zalloc(md_size);
    if (hash == NULL || z == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!sm2_compute_z_digest(z, digest, id, id_len, key)) {
        /* SM2err already called */
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, z, md_size)
            || !EVP_DigestUpdate(hash, msg, msg_len)
               /* reuse z buffer to hold H(Z || M) */
            || !EVP_DigestFinal(hash, z, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_EVP_LIB);
        goto done;
    }

    e = BN_bin2bn(z, md_size, NULL);
    if (e == NULL)
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_INTERNAL_ERROR);

 done:
    OPENSSL_free(z);
    EVP_MD_CTX_free(hash);
    return e;
}

static ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e)
{
    const BIGNUM *dA = EC_KEY_get0_private_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    ECDSA_SIG *sig = NULL;
    EC_POINT *kG = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *rk = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *tmp = NULL;

    kG = EC_POINT_new(group);
    ctx = BN_CTX_new();
    if (kG == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    rk = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (tmp == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = BN_new();
    s = BN_new();

    if (r == NULL || s == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    for (;;) {
        if (!BN_priv_rand_range(k, order)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
                || !EC_POINT_get_affine_coordinates(group, kG, x1, NULL,
                                                    ctx)
                || !BN_mod_add(r, e, x1, order, ctx)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        /* try again if r == 0 or r+k == n */
        if (BN_is_zero(r))
            continue;

        if (!BN_add(rk, r, k)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        if (BN_cmp(rk, order) == 0)
            continue;

        if (!BN_add(s, dA, BN_value_one())
                || !ec_group_do_inverse_ord(group, s, s, ctx)
                || !BN_mod_mul(tmp, dA, r, order, ctx)
                || !BN_sub(tmp, k, tmp)
                || !BN_mod_mul(s, s, tmp, order, ctx)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_BN_LIB);
            goto done;
        }

        sig = ECDSA_SIG_new();
        if (sig == NULL) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
            goto done;
        }

         /* takes ownership of r and s */
        ECDSA_SIG_set0(sig, r, s);
        break;
    }

 done:
    if (sig == NULL) {
        BN_free(r);
        BN_free(s);
    }

    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    return sig;
}

static int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig,
                          const BIGNUM *e)
{
    int ret = 0;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    BN_CTX *ctx = NULL;
    EC_POINT *pt = NULL;
    BIGNUM *t = NULL;
    BIGNUM *x1 = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    ctx = BN_CTX_new();
    pt = EC_POINT_new(group);
    if (ctx == NULL || pt == NULL) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    t = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    if (x1 == NULL) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /*
     * B1: verify whether r' in [1,n-1], verification failed if not
     * B2: vefify whether s' in [1,n-1], verification failed if not
     * B3: set M'~=ZA || M'
     * B4: calculate e'=Hv(M'~)
     * B5: calculate t = (r' + s') modn, verification failed if t=0
     * B6: calculate the point (x1', y1')=[s']G + [t]PA
     * B7: calculate R=(e'+x1') modn, verfication pass if yes, otherwise failed
     */

    ECDSA_SIG_get0(sig, &r, &s);

    if (BN_cmp(r, BN_value_one()) < 0
            || BN_cmp(s, BN_value_one()) < 0
            || BN_cmp(order, r) <= 0
            || BN_cmp(order, s) <= 0) {
        SM2err(SM2_F_SM2_SIG_VERIFY, SM2_R_BAD_SIGNATURE);
        goto done;
    }

    if (!BN_mod_add(t, r, s, order, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    if (BN_is_zero(t)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, SM2_R_BAD_SIGNATURE);
        goto done;
    }

    if (!EC_POINT_mul(group, pt, s, EC_KEY_get0_public_key(key), t, ctx)
            || !EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_EC_LIB);
        goto done;
    }

    if (!BN_mod_add(t, e, x1, order, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    if (BN_cmp(r, t) == 0)
        ret = 1;

 done:
    EC_POINT_free(pt);
    BN_CTX_free(ctx);
    return ret;
}

ECDSA_SIG *sm2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *sig = NULL;

    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    sig = sm2_sig_gen(key, e);

 done:
    BN_free(e);
    return sig;
}

int sm2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *sig,
                  const uint8_t *id,
                  const size_t id_len,
                  const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    int ret = 0;

    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    ret = sm2_sig_verify(key, sig, e);

 done:
    BN_free(e);
    return ret;
}

int sm2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *s = NULL;
    int sigleni;
    int ret = -1;

    e = BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
       SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
       goto done;
    }

    s = sm2_sig_gen(eckey, e);

    sigleni = i2d_ECDSA_SIG(s, &sig);
    if (sigleni < 0) {
       SM2err(SM2_F_SM2_SIGN, ERR_R_INTERNAL_ERROR);
       goto done;
    }
    *siglen = (unsigned int)sigleni;

    ret = 1;

 done:
    ECDSA_SIG_free(s);
    BN_free(e);
    return ret;
}

int sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s = NULL;
    BIGNUM *e = NULL;
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL) {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_INVALID_ENCODING);
        goto done;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sig, der, derlen) != 0) {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_INVALID_ENCODING);
        goto done;
    }

    e = BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    ret = sm2_sig_verify(eckey, s, e);

 done:
    OPENSSL_free(der);
    BN_free(e);
    ECDSA_SIG_free(s);
    return ret;
}



static int GMold_sm2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **xp)
{
	int ret = 0;
	const EC_GROUP *ec_group;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL;
	BIGNUM *x = NULL;
	BIGNUM *order = NULL;
	EC_POINT *point = NULL;

	if (ec_key == NULL || (ec_group = EC_KEY_get0_group(ec_key)) == NULL) {
		return 0;
	}

	if (ctx_in == NULL)  {
		if ((ctx = BN_CTX_new()) == NULL) {
			return 0;
		}
	}
	else {
		ctx = ctx_in;
	}

	k = BN_new();
	x = BN_new();
	order = BN_new();
	if (!k || !x || !order) {
		goto end;
	}

        if (!GMold_EC_GROUP_get_order(ec_group, order, ctx)) {
		goto end;
	}

	if ((point = EC_POINT_new(ec_group)) == NULL) {
		goto end;
	}

	do {
		/* get random k */
		do {
                        if (!GMold_BN_rand_range(k, order)) {
				goto end;
			}

		} while (BN_is_zero(k));

		/* compute r the x-coordinate of generator * k */
                if (!GMold_EC_POINT_mul(ec_group, point, k, NULL, NULL, ctx)) {
			goto end;
		}

                if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == GMold_NID_X9_62_prime_field) {
                        if (!GMold_EC_POINT_get_affine_coordinates_GFp(ec_group, point, x, NULL, ctx)) {
				goto end;
			}
		} else /* NID_X9_62_characteristic_two_field */ {
			if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, x, NULL, ctx)) {
				goto end;
			}
		}

                if (!GMold_BN_nnmod(x, x, order, ctx)) {
			goto end;
		}

	} while (BN_is_zero(x));

	/* clear old values if necessary */
	BN_clear_free(*kp);
	BN_clear_free(*xp);

	/* save the pre-computed values  */
	*kp = k;
	*xp = x;
	ret = 1;

end:
	if (!ret) {
		BN_clear_free(k);
		BN_clear_free(x);
	}
	if (!ctx_in) {
		BN_CTX_free(ctx);
	}
	BN_free(order);
	EC_POINT_free(point);

	return(ret);
}

static ECDSA_SIG *GMold_sm2_do_sign(const unsigned char *dgst, int dgstlen,
	const BIGNUM *in_k, const BIGNUM *in_x, EC_KEY *ec_key)
{
	int ok = 0;
	ECDSA_SIG *ret = NULL;
	const EC_GROUP *ec_group;
	const BIGNUM *priv_key;
	const BIGNUM *ck;
	BIGNUM *k = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	BIGNUM *e = NULL;
	BIGNUM *bn = NULL;
	int i;

	ec_group = EC_KEY_get0_group(ec_key);
	priv_key = EC_KEY_get0_private_key(ec_key);
	if (!ec_group || !priv_key) {
		return NULL;
	}

	if (!(ret = ECDSA_SIG_new())) {
		return NULL;
	}
	ret->r = BN_new();
	ret->s = BN_new();
	ctx = BN_CTX_new();
	order = BN_new();
	e = BN_new();
	bn = BN_new();
	if (!ret->r || !ret->s || !ctx || !order || !e || !bn) {
		goto end;
	}
        if (!GMold_EC_GROUP_get_order(ec_group, order, ctx)) {
		goto end;
	}

	/* convert dgst to e */
        i = GMold_BN_num_bits(order);

        if (!GMold_BN_bin2bn(dgst, dgstlen, e)) {
		goto end;
	}

	do {
		/* use or compute k and (kG).x */
		if (!in_k || !in_x) {
			if (!GMold_sm2_sign_setup(ec_key, ctx, &k, &ret->r)) {
				goto end;
			}
			ck = k;
		} else {
			ck = in_k;
                        if (!GMold_BN_copy(ret->r, in_x)) {
				goto end;
			}
		}

		/* r = e + x (mod n) */
                if (!GMold_BN_mod_add(ret->r, ret->r, e, order, ctx)) {
			goto end;
		}

                if (!GMold_BN_mod_add(bn, ret->r, ck, order, ctx)) {
			goto end;
		}

		/* check r != 0 && r + k != n */
		if (BN_is_zero(ret->r) || BN_is_zero(bn)) {
			if (in_k && in_x) {
				goto end;
			} else
				continue;
		}

		/* s = ((1 + d)^-1 * (k - rd)) mod n */
                if (!GMold_BN_set_word(bn,1)) {
			goto end;
		}

                if (!GMold_BN_mod_add(ret->s, priv_key, bn, order, ctx)) {
			goto end;
		}
                if (!GMold_BN_mod_inverse(ret->s, ret->s, order, ctx)) {
			goto end;
		}

                if (!GMold_BN_mod_mul(bn, ret->r, priv_key, order, ctx)) {
			goto end;
		}
                if (!GMold_BN_mod_sub(bn, ck, bn, order, ctx)) {
			goto end;
		}
                if (!GMold_BN_mod_mul(ret->s, ret->s, bn, order, ctx)) {
			goto end;
		}

		/* check s != 0 */
		if (BN_is_zero(ret->s)) {
			if (in_k && in_x) {
				goto end;
			}
		} else {
			break;
		}

	} while (1);

	ok = 1;

end:
	if (!ok) {
		ECDSA_SIG_free(ret);
		ret = NULL;
	}
	BN_free(k);
	BN_CTX_free(ctx);
	BN_free(order);
	BN_free(e);
	BN_free(bn);

	return ret;
}


ECDSA_SIG *GMold_SM2_do_sign_ex(const unsigned char *dgst, int dgstlen,
	const BIGNUM *kp, const BIGNUM *xp, EC_KEY *ec_key)
{
	return GMold_sm2_do_sign(dgst, dgstlen, kp, xp, ec_key);
}

int GMold_SM2_sign_ex(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen,
	const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key)
{
	ECDSA_SIG *s;

    GMold_RAND_seed(dgst, dgstlen);

	if (!(s = GMold_SM2_do_sign_ex(dgst, dgstlen, k, x, ec_key))) {
		*siglen = 0;
		return 0;
	}

        *siglen = GMold_i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);

	return 1;
}

int GMold_SM2_sign(int type, const unsigned char *dgst, int dgstlen,
	unsigned char *sig, unsigned int *siglen, EC_KEY *ec_key)
{
	return GMold_SM2_sign_ex(type, dgst, dgstlen, sig, siglen, NULL, NULL, ec_key);
}

int GMold_sm2_do_verify(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
	int ret = -1;
	const EC_GROUP *ec_group;
	const EC_POINT *pub_key;
	EC_POINT *point = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	BIGNUM *e = NULL;
	BIGNUM *t = NULL;
	int i;

	if (!sig || !ec_key ||
		!(ec_group = EC_KEY_get0_group(ec_key)) ||
		!(pub_key  = EC_KEY_get0_public_key(ec_key))) {

		return -1;
	}

	ctx = BN_CTX_new();
	order = BN_new();
	e = BN_new();
	t = BN_new();
	if (!ctx || !order || !e || !t) {
		goto end;
	}
        if (!GMold_EC_GROUP_get_order(ec_group, order, ctx)) {
		goto end;
	}

	/* check r, s in [1, n-1] and r + s != 0 (mod n) */
	if (BN_is_zero(sig->r) ||
		BN_is_negative(sig->r) ||
                BN_ucmp(sig->r, order) >= 0 ||
		BN_is_zero(sig->s) ||
		BN_is_negative(sig->s) ||
		BN_ucmp(sig->s, order) >= 0) {

		ret = 0;
		goto end;
	}

	/* check t = r + s != 0 */
        if (!GMold_BN_mod_add(t, sig->r, sig->s, order, ctx)) {
		goto end;
	}
	if (BN_is_zero(t)) {
		ret = 0;
		goto end;
	}

	/* convert digest to e */
        i = GMold_BN_num_bits(order);

        if (!GMold_BN_bin2bn(dgst, dgstlen, e)) {
		goto end;
	}


	/* compute (x, y) = sG + tP, P is pub_key */
	if (!(point = EC_POINT_new(ec_group))) {
		goto end;
	}
        if (!GMold_EC_POINT_mul(ec_group, point, sig->s, pub_key, t, ctx)) {
		goto end;
	}
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == GMold_NID_X9_62_prime_field) {
                if (!GMold_EC_POINT_get_affine_coordinates_GFp(ec_group, point, t, NULL, ctx)) {
			goto end;
		}
	} else /* NID_X9_62_characteristic_two_field */ {
		if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, t, NULL, ctx)) {
			goto end;
		}
	}
        if (!GMold_BN_nnmod(t, t, order, ctx)) {
		goto end;
	}

	/* check (sG + tP).x + e  == sig.r */
        if (!GMold_BN_mod_add(t, t, e, order, ctx)) {
		goto end;
	}
	if (BN_ucmp(t, sig->r) == 0) {
		ret = 1;
	} else {
		ret = 0;
	}

end:
	EC_POINT_free(point);
	BN_free(order);
	BN_free(e);
	BN_free(t);
	BN_CTX_free(ctx);
	return ret;
}

int GMold_SM2_do_verify(const unsigned char *dgst, int dgstlen,
	const ECDSA_SIG *sig, EC_KEY *ec_key)
{
	return GMold_sm2_do_verify(dgst, dgstlen, sig, ec_key);
}

int GMold_SM2_verify(int type, const unsigned char *dgst, int dgstlen,
	const unsigned char *sig, int siglen, EC_KEY *ec_key)
{
	ECDSA_SIG *s;
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	int derlen = -1;
	int ret = -1;

	if (!(s = ECDSA_SIG_new())) {
		return ret;
	}
	if (!GMold_d2i_ECDSA_SIG(&s, &p, siglen)) {
		goto err;
	}
        derlen = GMold_i2d_ECDSA_SIG(s, &der);
	if (derlen != siglen || memcmp(sig, der, derlen)) {
		goto err;
	}

	ret = GMold_SM2_do_verify(dgst, dgstlen, s, ec_key);

err:
	if (derlen > 0) {
		OPENSSL_cleanse(der, derlen);
		OPENSSL_free(der);
	}

	ECDSA_SIG_free(s);
	return ret;
}
