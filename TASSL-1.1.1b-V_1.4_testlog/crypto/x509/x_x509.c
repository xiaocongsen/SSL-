/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "internal/x509_int.h"

ASN1_SEQUENCE_enc(X509_CINF, enc, 0) = {
        ASN1_EXP_OPT(X509_CINF, version, ASN1_INTEGER, 0),
        ASN1_EMBED(X509_CINF, serialNumber, ASN1_INTEGER),
        ASN1_EMBED(X509_CINF, signature, X509_ALGOR),
        ASN1_SIMPLE(X509_CINF, issuer, X509_NAME),
        ASN1_EMBED(X509_CINF, validity, X509_VAL),
        ASN1_SIMPLE(X509_CINF, subject, X509_NAME),
        ASN1_SIMPLE(X509_CINF, key, X509_PUBKEY),
        ASN1_IMP_OPT(X509_CINF, issuerUID, ASN1_BIT_STRING, 1),
        ASN1_IMP_OPT(X509_CINF, subjectUID, ASN1_BIT_STRING, 2),
        ASN1_EXP_SEQUENCE_OF_OPT(X509_CINF, extensions, X509_EXTENSION, 3)
} ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF)

IMPLEMENT_ASN1_FUNCTIONS(X509_CINF)
/* X509 top level structure needs a bit of customisation */
// typedef struct ASN1_AUX_st {
//     void *app_data;
//     int flags;
//     int ref_offset;             /* Offset of reference value */
//     int ref_lock;               /* Lock type to use */
//     ASN1_aux_cb *asn1_cb;
//     int enc_offset;             /* Offset of ASN1_ENCODING structure */
// } ASN1_AUX;
static const ASN1_AUX GMold_X509_CINF_aux = {
        NULL, ASN1_AFLG_ENCODING, 0, 0, 0, ((size_t)&(((X509_CINF*)0)->enc))
        };
static const ASN1_TEMPLATE GMold_X509_CINF_seq_tt[] = {
        { (ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL), (0), ((size_t)&(((X509_CINF*)0)->version)), "version", (&(GMold_ASN1_INTEGER_it)) },
        { (ASN1_TFLG_EMBED), (0), ((size_t)&(((X509_CINF*)0)->serialNumber)), "serialNumber", (&(GMold_ASN1_INTEGER_it)) },
        { (ASN1_TFLG_EMBED), (0), ((size_t)&(((X509_CINF*)0)->signature)), "signature", (&(GMold_X509_ALGOR_it)) },
        { (0), (0), ((size_t)&(((X509_CINF*)0)->issuer)), "issuer", (&(GMold_X509_NAME_it)) },
        { (ASN1_TFLG_EMBED), (0), ((size_t)&(((X509_CINF*)0)->validity)), "validity", (&(GMold_X509_VAL_it)) },
        { (0), (0), ((size_t)&(((X509_CINF*)0)->subject)), "subject", (&(GMold_X509_NAME_it)) },
        { (0), (0), ((size_t)&(((X509_CINF*)0)->key)), "key", (&(GMold_X509_PUBKEY_it)) },
        { (ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL), (1), ((size_t)&(((X509_CINF*)0)->issuerUID)), "issuerUID", (&(GMold_ASN1_BIT_STRING_it)) },
        { (ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL), (2), ((size_t)&(((X509_CINF*)0)->subjectUID)), "subjectUID", (&(GMold_ASN1_BIT_STRING_it)) },
        { (ASN1_TFLG_EXPLICIT | ASN1_TFLG_SEQUENCE_OF|ASN1_TFLG_OPTIONAL), (3), ((size_t)&(((X509_CINF*)0)->extensions)), "extensions", (&(GMold_X509_EXTENSION_it)) }
};

// struct ASN1_ITEM_st {
//     char itype;                 /* The item type, primitive, SEQUENCE, CHOICE
//                                  * or extern */
//     long utype;                 /* underlying type */
//     const ASN1_TEMPLATE *templates; /* If SEQUENCE or CHOICE this contains
//                                      * the contents */
//     long tcount;                /* Number of templates if SEQUENCE or CHOICE */
//     const void *funcs;          /* functions that handle this type */
//     long size;                  /* Structure size (usually) */
//     const char *sname;          /* Structure name */
// };
const ASN1_ITEM GMold_X509_CINF_it = {
         ASN1_ITYPE_SEQUENCE, V_ASN1_SEQUENCE, GMold_X509_CINF_seq_tt,
         sizeof(GMold_X509_CINF_seq_tt) / sizeof(ASN1_TEMPLATE), &GMold_X509_CINF_aux, sizeof(X509_CINF), "X509_CINF"
         };


extern void policy_cache_free(X509_POLICY_CACHE *cache);

static int x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                   void *exarg)
{
//    printf("ddddddddddd x509_cb \n");
    X509 *ret = (X509 *)*pval;

    switch (operation) {

    case ASN1_OP_D2I_PRE:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        X509_CERT_AUX_free(ret->aux);
        ASN1_OCTET_STRING_free(ret->skid);
        AUTHORITY_KEYID_free(ret->akid);
        CRL_DIST_POINTS_free(ret->crldp);
        policy_cache_free(ret->policy_cache);
        GENERAL_NAMES_free(ret->altname);
        NAME_CONSTRAINTS_free(ret->nc);
#ifndef OPENSSL_NO_RFC3779
        sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
        ASIdentifiers_free(ret->rfc3779_asid);
#endif

        /* fall thru */

    case ASN1_OP_NEW_POST:
        ret->ex_cached = 0;
        ret->ex_kusage = 0;
        ret->ex_xkusage = 0;
        ret->ex_nscert = 0;
        ret->ex_flags = 0;
        ret->ex_pathlen = -1;
        ret->ex_pcpathlen = -1;
        ret->skid = NULL;
        ret->akid = NULL;
        ret->policy_cache = NULL;
        ret->altname = NULL;
        ret->nc = NULL;
#ifndef OPENSSL_NO_RFC3779
        ret->rfc3779_addr = NULL;
        ret->rfc3779_asid = NULL;
#endif
        ret->aux = NULL;
        ret->crldp = NULL;
        if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data))
            return 0;
        break;

    case ASN1_OP_FREE_POST:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        X509_CERT_AUX_free(ret->aux);
        ASN1_OCTET_STRING_free(ret->skid);
        AUTHORITY_KEYID_free(ret->akid);
        CRL_DIST_POINTS_free(ret->crldp);
        policy_cache_free(ret->policy_cache);
        GENERAL_NAMES_free(ret->altname);
        NAME_CONSTRAINTS_free(ret->nc);
#ifndef OPENSSL_NO_RFC3779
        sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
        ASIdentifiers_free(ret->rfc3779_asid);
#endif
        break;

    }

    return 1;

}


static int GMold_x509_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it, void *exarg)
{
    X509 *ret = (X509 *)*pval;

    switch (operation) {

    case ASN1_OP_NEW_POST:
        ret->ex_flags = 0;
        ret->ex_pathlen = -1;
        ret->ex_pcpathlen = -1;
        ret->skid = NULL;
        ret->akid = NULL;
        ret->rfc3779_addr = NULL;
        ret->rfc3779_asid = NULL;
        ret->aux = NULL;
        ret->crldp = NULL;
        if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data))
            return 0;
        break;

    case ASN1_OP_FREE_POST:
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509, ret, &ret->ex_data);
        X509_CERT_AUX_free(ret->aux);
        ASN1_OCTET_STRING_free(ret->skid);
        AUTHORITY_KEYID_free(ret->akid);
        CRL_DIST_POINTS_free(ret->crldp);
        policy_cache_free(ret->policy_cache);
        GENERAL_NAMES_free(ret->altname);
        NAME_CONSTRAINTS_free(ret->nc);
        sk_IPAddressFamily_pop_free(ret->rfc3779_addr, IPAddressFamily_free);
        ASIdentifiers_free(ret->rfc3779_asid);
        break;

    }

    return 1;

}


ASN1_SEQUENCE_ref(X509, x509_cb) = {
        ASN1_EMBED(X509, cert_info, X509_CINF),
        ASN1_EMBED(X509, sig_alg, X509_ALGOR),
        ASN1_EMBED(X509, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_ref(X509, X509)


X509 *d2i_X509(X509 **a, const unsigned char **in, long len)
{
    printf("ddddddddddddddddddddddddddd d2i_X509\n");
    return (X509 *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(X509));
}
int i2d_X509(X509 *a, unsigned char **out)
{
        printf("dddddddddddddd i2d_X509 \n");
    return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(X509));
}
X509 *X509_new(void)
{
    return (X509 *)ASN1_item_new(ASN1_ITEM_rptr(X509));
}
void X509_free(X509 *a)
{
    ASN1_item_free((ASN1_VALUE *)a, ASN1_ITEM_rptr(X509));
}
// typedef struct ASN1_AUX_st {
//     void *app_data;
//     int flags;
//     int ref_offset;             /* Offset of reference value */
//     int ref_lock;               /* Lock type to use */
//     ASN1_aux_cb *asn1_cb;
//     int enc_offset;             /* Offset of ASN1_ENCODING structure */
// } ASN1_AUX;
static const ASN1_AUX GMold_X509_aux = {
    NULL, ASN1_AFLG_REFCOUNT, ((size_t)&(((X509*)0)->references)), ((size_t)&(((X509*)0)->lock)), GMold_x509_cb, 0
    };

// struct ASN1_TEMPLATE_st {
//     unsigned long flags;        /* Various flags */
//     long tag;                   /* tag, not used if no tagging */
//     unsigned long offset;       /* Offset of this field in structure */
//     const char *field_name;     /* Field name */
//     ASN1_ITEM_EXP *item;        /* Relevant ASN1_ITEM or ASN1_ADB */
// };
static const ASN1_TEMPLATE GMold_X509_seq_tt[] = {
        { (ASN1_TFLG_EMBED), (0), ((size_t)&(((X509*)0)->cert_info)), "cert_info", (&(GMold_X509_CINF_it)) },
        { (ASN1_TFLG_EMBED), (0), ((size_t)&(((X509*)0)->sig_alg)), "sig_alg", (&(GMold_X509_ALGOR_it)) },
        { (ASN1_TFLG_EMBED), (0), ((size_t)&(((X509*)0)->signature)), "signature", (&(GMold_ASN1_BIT_STRING_it)) }
};
// struct ASN1_ITEM_st {
//     char itype;                 /* The item type, primitive, SEQUENCE, CHOICE
//                                  * or extern */
//     long utype;                 /* underlying type */
//     const ASN1_TEMPLATE *templates; /* If SEQUENCE or CHOICE this contains
//                                      * the contents */
//     long tcount;                /* Number of templates if SEQUENCE or CHOICE */
//     const void *funcs;          /* functions that handle this type */
//     long size;                  /* Structure size (usually) */
//     const char *sname;          /* Structure name */
// };
const ASN1_ITEM GMold_X509_it = {
    ASN1_ITYPE_SEQUENCE, V_ASN1_SEQUENCE, GMold_X509_seq_tt, sizeof(GMold_X509_seq_tt) / sizeof(ASN1_TEMPLATE),
    &GMold_X509_aux, sizeof(X509), "X509"
};
X509 *GMold_d2i_X509(X509 **a, const unsigned char **in, long len)
{
    return (X509 *)GMold_ASN1_item_d2i((ASN1_VALUE **)a, in, len, &GMold_X509_it);
}
int GMold_i2d_X509(X509 *a, unsigned char **out)
{
    return GMold_ASN1_item_i2d((ASN1_VALUE *)a, out, &GMold_X509_it);
}

IMPLEMENT_ASN1_DUP_FUNCTION(X509)

int X509_set_ex_data(X509 *r, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&r->ex_data, idx, arg);
}

void *X509_get_ex_data(X509 *r, int idx)
{
    return CRYPTO_get_ex_data(&r->ex_data, idx);
}

/*
 * X509_AUX ASN1 routines. X509_AUX is the name given to a certificate with
 * extra info tagged on the end. Since these functions set how a certificate
 * is trusted they should only be used when the certificate comes from a
 * reliable source such as local storage.
 */

X509 *d2i_X509_AUX(X509 **a, const unsigned char **pp, long length)
{
    const unsigned char *q;
    X509 *ret;
    int freeret = 0;

    /* Save start position */
    q = *pp;

    if (a == NULL || *a == NULL)
        freeret = 1;
    ret = d2i_X509(a, &q, length);
    /* If certificate unreadable then forget it */
    if (ret == NULL)
        return NULL;
    /* update length */
    length -= q - *pp;
    if (length > 0 && !d2i_X509_CERT_AUX(&ret->aux, &q, length))
        goto err;
    *pp = q;
    return ret;
 err:
    if (freeret) {
        X509_free(ret);
        if (a)
            *a = NULL;
    }
    return NULL;
}

/*
 * Serialize trusted certificate to *pp or just return the required buffer
 * length if pp == NULL.  We ultimately want to avoid modifying *pp in the
 * error path, but that depends on similar hygiene in lower-level functions.
 * Here we avoid compounding the problem.
 */
static int i2d_x509_aux_internal(X509 *a, unsigned char **pp)
{
    int length, tmplen;
    unsigned char *start = pp != NULL ? *pp : NULL;

    /*
     * This might perturb *pp on error, but fixing that belongs in i2d_X509()
     * not here.  It should be that if a == NULL length is zero, but we check
     * both just in case.
     */
    length = i2d_X509(a, pp);
    if (length <= 0 || a == NULL)
        return length;

    tmplen = i2d_X509_CERT_AUX(a->aux, pp);
    if (tmplen < 0) {
        if (start != NULL)
            *pp = start;
        return tmplen;
    }
    length += tmplen;

    return length;
}

/*
 * Serialize trusted certificate to *pp, or just return the required buffer
 * length if pp == NULL.
 *
 * When pp is not NULL, but *pp == NULL, we allocate the buffer, but since
 * we're writing two ASN.1 objects back to back, we can't have i2d_X509() do
 * the allocation, nor can we allow i2d_X509_CERT_AUX() to increment the
 * allocated buffer.
 */
int i2d_X509_AUX(X509 *a, unsigned char **pp)
{
    int length;
    unsigned char *tmp;

    /* Buffer provided by caller */
    if (pp == NULL || *pp != NULL)
        return i2d_x509_aux_internal(a, pp);

    /* Obtain the combined length */
    if ((length = i2d_x509_aux_internal(a, NULL)) <= 0)
        return length;

    /* Allocate requisite combined storage */
    *pp = tmp = OPENSSL_malloc(length);
    if (tmp == NULL) {
        X509err(X509_F_I2D_X509_AUX, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    /* Encode, but keep *pp at the originally malloced pointer */
    length = i2d_x509_aux_internal(a, &tmp);
    if (length <= 0) {
        OPENSSL_free(*pp);
        *pp = NULL;
    }
    return length;
}

int i2d_re_X509_tbs(X509 *x, unsigned char **pp)
{
    x->cert_info.enc.modified = 1;
    return i2d_X509_CINF(&x->cert_info, pp);
}

void X509_get0_signature(const ASN1_BIT_STRING **psig,
                         const X509_ALGOR **palg, const X509 *x)
{
    if (psig)
        *psig = &x->signature;
    if (palg)
        *palg = &x->sig_alg;
}

int X509_get_signature_nid(const X509 *x)
{
    printf("ddddddddddddddddd X509_get_signature_nid\n");
    return OBJ_obj2nid(x->sig_alg.algorithm);
}

int GMold_X509_get_signature_nid(const X509 *x)
{
    return GMold_OBJ_obj2nid(x->sig_alg.algorithm);
}
