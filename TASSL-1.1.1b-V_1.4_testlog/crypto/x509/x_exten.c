/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "x509_lcl.h"

ASN1_SEQUENCE(X509_EXTENSION) = {
        ASN1_SIMPLE(X509_EXTENSION, object, ASN1_OBJECT),
        ASN1_OPT(X509_EXTENSION, critical, ASN1_BOOLEAN),
        ASN1_EMBED(X509_EXTENSION, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(X509_EXTENSION)

static const ASN1_TEMPLATE GMold_X509_EXTENSION_seq_tt[] = {
        { (0), (0), ((size_t)&(((X509_EXTENSION*)0)->object)), "object", (&(GMold_ASN1_OBJECT_it)) },
        { (ASN1_TFLG_OPTIONAL), (0), offsetof(X509_EXTENSION, critical), "critical", (&(GMold_ASN1_BOOLEAN_it)) },
        { (ASN1_TFLG_EMBED), (0), ((size_t)&(((X509_EXTENSION*)0)->value)), "value", (&(GMold_ASN1_OCTET_STRING_it)) }
}; 
const ASN1_ITEM GMold_X509_EXTENSION_it = { 
        ASN1_ITYPE_SEQUENCE, V_ASN1_SEQUENCE, GMold_X509_EXTENSION_seq_tt, 
        sizeof(GMold_X509_EXTENSION_seq_tt) / sizeof(ASN1_TEMPLATE), NULL, 
        sizeof(X509_EXTENSION), "X509_EXTENSION" 
        };


ASN1_ITEM_TEMPLATE(X509_EXTENSIONS) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, Extension, X509_EXTENSION)
ASN1_ITEM_TEMPLATE_END(X509_EXTENSIONS)

IMPLEMENT_ASN1_FUNCTIONS(X509_EXTENSION)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(X509_EXTENSIONS, X509_EXTENSIONS, X509_EXTENSIONS)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_EXTENSION)
