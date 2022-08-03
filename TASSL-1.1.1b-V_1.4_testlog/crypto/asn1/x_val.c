/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
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

ASN1_SEQUENCE(X509_VAL) = {
        ASN1_SIMPLE(X509_VAL, notBefore, ASN1_TIME),
        ASN1_SIMPLE(X509_VAL, notAfter, ASN1_TIME)
} ASN1_SEQUENCE_END(X509_VAL)

static const ASN1_TEMPLATE GMold_X509_VAL_seq_tt[] = {
        { (0), (0), ((size_t)&(((X509_VAL*)0)->notBefore)), "notBefore", (&(GMold_ASN1_TIME_it)) },
        { (0), (0), ((size_t)&(((X509_VAL*)0)->notAfter)), "notAfter", (&(GMold_ASN1_TIME_it)) }
};
const ASN1_ITEM GMold_X509_VAL_it = { 
        ASN1_ITYPE_SEQUENCE, V_ASN1_SEQUENCE, GMold_X509_VAL_seq_tt, 
        sizeof(GMold_X509_VAL_seq_tt) / sizeof(ASN1_TEMPLATE), NULL, sizeof(X509_VAL), "X509_VAL" 
};

IMPLEMENT_ASN1_FUNCTIONS(X509_VAL)
