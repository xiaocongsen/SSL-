/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>

IMPLEMENT_PEM_rw(X509, X509, PEM_STRING_X509, X509)

X509 *GMold_PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u)
{
    return PEM_ASN1_read_bio((d2i_of_void *)GMold_d2i_X509, PEM_STRING_X509,bp,(void **)x,cb,u);
}
