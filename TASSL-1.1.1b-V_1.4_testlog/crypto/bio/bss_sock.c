/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <errno.h>
#include "bio_lcl.h"
#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_SOCK

# include <openssl/bio.h>

# ifdef WATT32
/* Watt-32 uses same names */
#  undef sock_write
#  undef sock_read
#  undef sock_puts
#  define sock_write SockWrite
#  define sock_read  SockRead
#  define sock_puts  SockPuts
# endif

static int sock_write(BIO *h, const char *buf, int num);
static int sock_read(BIO *h, char *buf, int size);
static int sock_puts(BIO *h, const char *str);
static long sock_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int sock_new(BIO *h);
static int sock_free(BIO *data);
int BIO_sock_should_retry(int s);

static const BIO_METHOD methods_sockp = {
    BIO_TYPE_SOCKET,
    "socket",
    /* TODO: Convert to new style write function */
    bwrite_conv,
    sock_write,
    /* TODO: Convert to new style read function */
    bread_conv,
    sock_read,
    sock_puts,
    NULL,                       /* sock_gets,         */
    sock_ctrl,
    sock_new,
    sock_free,
    NULL,                       /* sock_callback_ctrl */
};

const BIO_METHOD *BIO_s_socket(void)
{
    return &methods_sockp;
}

BIO *BIO_new_socket(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(BIO_s_socket());
    if (ret == NULL)
        return NULL;
    BIO_set_fd(ret, fd, close_flag);
    return ret;
}

static int sock_new(BIO *bi)
{
    printf("dddddddddddddddd sock_new\n");
    bi->init = 0;
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = 0;
    return 1;
}

static int sock_free(BIO *a)
{
    printf("dddddddddddddddd sock_free\n");
    if (a == NULL)
        return 0;
    if (a->shutdown) {
        if (a->init) {
            BIO_closesocket(a->num);
        }
        a->init = 0;
        a->flags = 0;
    }
    return 1;
}

static int sock_read(BIO *b, char *out, int outl)
{
    int ret = 0;
    printf("dddddddddddddddd sock_read\n");
    if (out != NULL) {
        clear_socket_error();
        ret = readsocket(b->num, out, outl);
        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
        }
    }
    return ret;
}

static int sock_write(BIO *b, const char *in, int inl)
{
    int ret;
    printf("dddddddddddddddd sock_write\n");
    clear_socket_error();
    ret = writesocket(b->num, in, inl);
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return ret;
}

static long sock_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
    printf("dddddddddddddddd sock_ctrl\n");
    switch (cmd) {
    case BIO_C_SET_FD:      //设置socket描述符
        sock_free(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    default:
        ret = 0;
        break;
    }
    return ret;
}

static int sock_puts(BIO *bp, const char *str)
{
    int n, ret;
    printf("dddddddddddddddd sock_puts\n");
    n = strlen(str);
    ret = sock_write(bp, str, n);
    return ret;
}

int BIO_sock_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_socket_error();

        return BIO_sock_non_fatal_error(err);
    }
    return 0;
}

int BIO_sock_non_fatal_error(int err)
{
    switch (err) {
# if defined(OPENSSL_SYS_WINDOWS)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
    case ENOTCONN:
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif
        return 1;
    default:
        break;
    }
    return 0;
}



static int GMold_sock_write(BIO *h, const char *buf, int num);
static int GMold_sock_read(BIO *h, char *buf, int size);
static int GMold_sock_puts(BIO *h, const char *str);
static long GMold_sock_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int GMold_sock_new(BIO *h);
static int GMold_sock_free(BIO *data);
int GMold_BIO_sock_should_retry(int s);

static const BIO_METHOD GMold_methods_sockp = {
    BIO_TYPE_SOCKET,
    "socket",
    NULL,
    GMold_sock_write,
    NULL,
    GMold_sock_read,
    GMold_sock_puts,
    NULL,                       /* sock_gets, */
    GMold_sock_ctrl,
    GMold_sock_new,
    GMold_sock_free,
    NULL,
};

const BIO_METHOD *GMold_BIO_s_socket(void)
{
    return (&GMold_methods_sockp);
}

BIO *GMold_BIO_new_socket(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(GMold_BIO_s_socket());
    if (ret == NULL)
        return (NULL);
    BIO_set_fd(ret, fd, close_flag);
    return (ret);
}

static int GMold_sock_new(BIO *bi)
{
    printf("sock_new 1111111111 name:%s\n",bi->method->name);
    bi->init = 0;
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = 0;
    return (1);
}

static int GMold_sock_free(BIO *a)
{
    if (a == NULL)
        return (0);
//    printf("sock_free 1111111111 name:%s\n",a->method->name);
    if (a->shutdown) {
        if (a->init) {
            BIO_closesocket(a->num);
        }
        a->init = 0;
        a->flags = 0;
    }
    return (1);
}

static int GMold_sock_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out != NULL) {
        clear_socket_error();
        ret = readsocket(b->num, out, outl);
        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (GMold_BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
        }
    }
    printf("sock_read 22222222 ret:%d name:%s\n",ret,b->method->name);
    return (ret);
}

static int GMold_sock_write(BIO *b, const char *in, int inl)
{
    int ret;

    clear_socket_error();
//    for(int i=0; i< inl;++i)
//    {
//        printf("xcs write[i:%d][%02X]\n",i,in[i]);
//    }
    ret = writesocket(b->num, in, inl);
//    printf("sock_write 1111111111 ret:%d name:%s\n",ret,b->method->name);
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (GMold_BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return (ret);
}

static long GMold_sock_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
    printf("GMold_sock_ctrl 1111111111 cmd:%d name:%s\n",cmd,b->method->name);
    switch (cmd) {
    case BIO_C_SET_FD:
        sock_free(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    default:
        ret = 0;
        break;
    }
    return (ret);
}

static int GMold_sock_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = GMold_sock_write(bp, str, n);
    printf("GMold_sock_puts 1111111111 ret:%d name:%s\n",ret,bp->method->name);
    return (ret);
}

int GMold_BIO_sock_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_socket_error();

        return (GMold_BIO_sock_non_fatal_error(err));
    }
    return (0);
}

int GMold_BIO_sock_non_fatal_error(int err)
{
    switch (err) {
# if defined(OPENSSL_SYS_WINDOWS)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
    case ENOTCONN:
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif
        return (1);
        /* break; */
    default:
        break;
    }
    return (0);
}


#endif                          /* #ifndef OPENSSL_NO_SOCK */
