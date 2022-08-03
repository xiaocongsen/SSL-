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

#ifndef HEADER_SM2_H
# define HEADER_SM2_H
# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_SM2

#  include <openssl/ec.h>

/* The default user id as specified in GM/T 0009-2012 */
#  define SM2_DEFAULT_USERID "1234567812345678"

int sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key);

/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
ECDSA_SIG *sm2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len);

int sm2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *signature,
                  const uint8_t *id,
                  const size_t id_len,
                  const uint8_t *msg, size_t msg_len);

/*
 * SM2 signature generation.
 */
int sm2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

/*
 * SM2 signature verification.
 */
int sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int siglen, EC_KEY *eckey);

/*
 * SM2 encryption
 */
int sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                        size_t *ct_size);

int sm2_plaintext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
                       size_t *pt_size);

int sm2_encrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *msg,
                size_t msg_len,
                uint8_t *ciphertext_buf, size_t *ciphertext_len);

int sm2_decrypt(const EC_KEY *key,
                const EVP_MD *digest,
                const uint8_t *ciphertext,
                size_t ciphertext_len, uint8_t *ptext_buf, size_t *ptext_len);



#define SM2_DEFAULT_ID_GMT09			"1234567812345678"
#define SM2_DEFAULT_ID				SM2_DEFAULT_ID_GMT09
#define SM2_DEFAULT_ID_LENGTH			(sizeof(SM2_DEFAULT_ID) - 1)
#define SM2_MAX_ID_LENGTH			(SM2_MAX_ID_BITS/8)
#define EVP_PKEY_CTRL_EC_SCHEME	    	(EVP_PKEY_ALG_CTRL + 11)
#define EVP_PKEY_CTRL_SIGNER_ID		(EVP_PKEY_ALG_CTRL + 12)
#define EVP_PKEY_CTRL_GET_SIGNER_ID	(EVP_PKEY_ALG_CTRL + 13)
#define EVP_PKEY_CTRL_GET_SIGNER_ZID    (EVP_PKEY_ALG_CTRL + 14)
#define EVP_PKEY_CTRL_EC_ENCRYPT_PARAM  (EVP_PKEY_ALG_CTRL + 15)
#define EC_MAX_NBYTES  ((OPENSSL_ECC_MAX_FIELD_BITS + 7)/8)
#define SM2_MAX_PKEY_DATA_LENGTH		((EC_MAX_NBYTES + 1) * 6)
#define SM2_MAX_ID_BITS				65535
#define SM2_MAX_ID_LENGTH			(SM2_MAX_ID_BITS/8)

struct SM2CiphertextValue_st {
	BIGNUM *xCoordinate;
	BIGNUM *yCoordinate;
	ASN1_OCTET_STRING *hash;
	ASN1_OCTET_STRING *ciphertext;
};
typedef struct SM2CiphertextValue_st SM2CiphertextValue;
DECLARE_ASN1_FUNCTIONS(SM2CiphertextValue)
int i2o_SM2CiphertextValue(const EC_GROUP *group, const SM2CiphertextValue *cv,
	unsigned char **pout);
SM2CiphertextValue *o2i_SM2CiphertextValue(const EC_GROUP *group, const EVP_MD *md,
	SM2CiphertextValue **cv, const unsigned char **pin, long len);

SM2CiphertextValue *GMold_SM2_do_encrypt(const EVP_MD *md, const unsigned char *in, size_t inlen, EC_KEY *ec_key);
int GMold_SM2_do_decrypt(const EVP_MD *md, const SM2CiphertextValue *in, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int GMold_SM2_compute_id_digest(const EVP_MD *md, const char *id, size_t idlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int GMold_SM2_get_public_key_data(EC_KEY *ec_key, unsigned char *out, size_t *outlen);
# endif /* OPENSSL_NO_SM2 */
#endif
