/*
 * Copyright 2011-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "rand_lcl.h"
#include "internal/thread_once.h"
#include "internal/rand_int.h"
#include "internal/cryptlib_int.h"
#include <sys/types.h>
#include <unistd.h>

#if !(defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_VXWORKS) || defined(OPENSSL_SYS_DSPBIOS))
# include <sys/time.h>
#endif
#if defined(OPENSSL_SYS_VXWORKS)
# include <time.h>
#endif
/*
 * Support framework for NIST SP 800-90A DRBG
 *
 * See manual page RAND_DRBG(7) for a general overview.
 *
 * The OpenSSL model is to have new and free functions, and that new
 * does all initialization.  That is not the NIST model, which has
 * instantiation and un-instantiate, and re-use within a new/free
 * lifecycle.  (No doubt this comes from the desire to support hardware
 * DRBG, where allocation of resources on something like an HSM is
 * a much bigger deal than just re-setting an allocated resource.)
 */

/*
 * The three shared DRBG instances
 *
 * There are three shared DRBG instances: <master>, <public>, and <private>.
 */

/*
 * The <master> DRBG
 *
 * Not used directly by the application, only for reseeding the two other
 * DRBGs. It reseeds itself by pulling either randomness from os entropy
 * sources or by consuming randomness which was added by RAND_add().
 *
 * The <master> DRBG is a global instance which is accessed concurrently by
 * all threads. The necessary locking is managed automatically by its child
 * DRBG instances during reseeding.
 */
static RAND_DRBG *master_drbg;
/*
 * The <public> DRBG
 *
 * Used by default for generating random bytes using RAND_bytes().
 *
 * The <public> DRBG is thread-local, i.e., there is one instance per thread.
 */
static CRYPTO_THREAD_LOCAL public_drbg;
/*
 * The <private> DRBG
 *
 * Used by default for generating private keys using RAND_priv_bytes()
 *
 * The <private> DRBG is thread-local, i.e., there is one instance per thread.
 */
static CRYPTO_THREAD_LOCAL private_drbg;



/* NIST SP 800-90A DRBG recommends the use of a personalization string. */
static const char ossl_pers_string[] = "OpenSSL NIST SP 800-90A DRBG";

static CRYPTO_ONCE rand_drbg_init = CRYPTO_ONCE_STATIC_INIT;



static int rand_drbg_type = RAND_DRBG_TYPE;
static unsigned int rand_drbg_flags = RAND_DRBG_FLAGS;

static unsigned int master_reseed_interval = MASTER_RESEED_INTERVAL;
static unsigned int slave_reseed_interval  = SLAVE_RESEED_INTERVAL;

static time_t master_reseed_time_interval = MASTER_RESEED_TIME_INTERVAL;
static time_t slave_reseed_time_interval  = SLAVE_RESEED_TIME_INTERVAL;

/* A logical OR of all used DRBG flag bits (currently there is only one) */
static const unsigned int rand_drbg_used_flags =
    RAND_DRBG_FLAG_CTR_NO_DF;

static RAND_DRBG *drbg_setup(RAND_DRBG *parent);

static RAND_DRBG *rand_drbg_new(int secure,
                                int type,
                                unsigned int flags,
                                RAND_DRBG *parent);

void GMold_ASYNC_block_pause(void);
void GMold_ASYNC_unblock_pause(void);
/*
 * Set/initialize |drbg| to be of type |type|, with optional |flags|.
 *
 * If |type| and |flags| are zero, use the defaults
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags)
{
    int ret = 1;

    if (type == 0 && flags == 0) {
        type = rand_drbg_type;
        flags = rand_drbg_flags;
    }

    /* If set is called multiple times - clear the old one */
    if (drbg->type != 0 && (type != drbg->type || flags != drbg->flags)) {
        drbg->meth->uninstantiate(drbg);
        rand_pool_free(drbg->adin_pool);
        drbg->adin_pool = NULL;
    }

    drbg->state = DRBG_UNINITIALISED;
    drbg->flags = flags;
    drbg->type = type;

    switch (type) {
    default:
        drbg->type = 0;
        drbg->flags = 0;
        drbg->meth = NULL;
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    case 0:
        /* Uninitialized; that's okay. */
        drbg->meth = NULL;
        return 1;
    case NID_aes_128_ctr:
    case NID_aes_192_ctr:
    case NID_aes_256_ctr:
        ret = drbg_ctr_init(drbg);
        break;
    }

    if (ret == 0) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_ERROR_INITIALISING_DRBG);
    }
    return ret;
}

/*
 * Set/initialize default |type| and |flag| for new drbg instances.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_defaults(int type, unsigned int flags)
{
    int ret = 1;

    switch (type) {
    default:
        RANDerr(RAND_F_RAND_DRBG_SET_DEFAULTS, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    case NID_aes_128_ctr:
    case NID_aes_192_ctr:
    case NID_aes_256_ctr:
        break;
    }

    if ((flags & ~rand_drbg_used_flags) != 0) {
        RANDerr(RAND_F_RAND_DRBG_SET_DEFAULTS, RAND_R_UNSUPPORTED_DRBG_FLAGS);
        return 0;
    }

    rand_drbg_type  = type;
    rand_drbg_flags = flags;

    return ret;
}


/*
 * Allocate memory and initialize a new DRBG. The DRBG is allocated on
 * the secure heap if |secure| is nonzero and the secure heap is enabled.
 * The |parent|, if not NULL, will be used as random source for reseeding.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
static RAND_DRBG *rand_drbg_new(int secure,
                                int type,
                                unsigned int flags,
                                RAND_DRBG *parent)
{
    RAND_DRBG *drbg = secure ?
        OPENSSL_secure_zalloc(sizeof(*drbg)) : OPENSSL_zalloc(sizeof(*drbg));

    if (drbg == NULL) {
        RANDerr(RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    drbg->secure = secure && CRYPTO_secure_allocated(drbg);
    drbg->fork_count = rand_fork_count;
    drbg->parent = parent;

    if (parent == NULL) {
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
#ifndef RAND_DRBG_GET_RANDOM_NONCE
        drbg->get_nonce = rand_drbg_get_nonce;
        drbg->cleanup_nonce = rand_drbg_cleanup_nonce;
#endif

        drbg->reseed_interval = master_reseed_interval;
        drbg->reseed_time_interval = master_reseed_time_interval;
    } else {
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
        /*
         * Do not provide nonce callbacks, the child DRBGs will
         * obtain their nonce using random bits from the parent.
         */

        drbg->reseed_interval = slave_reseed_interval;
        drbg->reseed_time_interval = slave_reseed_time_interval;
    }

    if (RAND_DRBG_set(drbg, type, flags) == 0)
        goto err;

    if (parent != NULL) {
        rand_drbg_lock(parent);
        if (drbg->strength > parent->strength) {
            /*
             * We currently don't support the algorithm from NIST SP 800-90C
             * 10.1.2 to use a weaker DRBG as source
             */
            rand_drbg_unlock(parent);
            RANDerr(RAND_F_RAND_DRBG_NEW, RAND_R_PARENT_STRENGTH_TOO_WEAK);
            goto err;
        }
        rand_drbg_unlock(parent);
    }

    return drbg;

 err:
    RAND_DRBG_free(drbg);

    return NULL;
}

RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return rand_drbg_new(0, type, flags, parent);
}

RAND_DRBG *RAND_DRBG_secure_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return rand_drbg_new(1, type, flags, parent);
}

/*
 * Uninstantiate |drbg| and free all memory.
 */
void RAND_DRBG_free(RAND_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    if (drbg->meth != NULL)
        drbg->meth->uninstantiate(drbg);
    rand_pool_free(drbg->adin_pool);
    CRYPTO_THREAD_lock_free(drbg->lock);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DRBG, drbg, &drbg->ex_data);

    if (drbg->secure)
        OPENSSL_secure_clear_free(drbg, sizeof(*drbg));
    else
        OPENSSL_clear_free(drbg, sizeof(*drbg));
}

/*
 * Instantiate |drbg|, after it has been initialized.  Use |pers| and
 * |perslen| as prediction-resistance input.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_instantiate(RAND_DRBG *drbg,
                          const unsigned char *pers, size_t perslen)
{
    unsigned char *nonce = NULL, *entropy = NULL;
    size_t noncelen = 0, entropylen = 0;
    size_t min_entropy = drbg->strength;
    size_t min_entropylen = drbg->min_entropylen;
    size_t max_entropylen = drbg->max_entropylen;

    if (perslen > drbg->max_perslen) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE,
                RAND_R_PERSONALISATION_STRING_TOO_LONG);
        goto end;
    }

    if (drbg->meth == NULL) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE,
                RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        goto end;
    }

    if (drbg->state != DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE,
                drbg->state == DRBG_ERROR ? RAND_R_IN_ERROR_STATE
                                          : RAND_R_ALREADY_INSTANTIATED);
        goto end;
    }

    drbg->state = DRBG_ERROR;

    /*
     * NIST SP800-90Ar1 section 9.1 says you can combine getting the entropy
     * and nonce in 1 call by increasing the entropy with 50% and increasing
     * the minimum length to accomadate the length of the nonce.
     * We do this in case a nonce is require and get_nonce is NULL.
     */
    if (drbg->min_noncelen > 0 && drbg->get_nonce == NULL) {
        min_entropy += drbg->strength / 2;
        min_entropylen += drbg->min_noncelen;
        max_entropylen += drbg->max_noncelen;
    }

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_prop_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if(!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    if (drbg->get_entropy != NULL)
        entropylen = drbg->get_entropy(drbg, &entropy, min_entropy,
                                       min_entropylen, max_entropylen, 0);
    if (entropylen < min_entropylen
            || entropylen > max_entropylen) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (drbg->min_noncelen > 0 && drbg->get_nonce != NULL) {
        noncelen = drbg->get_nonce(drbg, &nonce, drbg->strength / 2,
                                   drbg->min_noncelen, drbg->max_noncelen);
        if (noncelen < drbg->min_noncelen || noncelen > drbg->max_noncelen) {
            RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_RETRIEVING_NONCE);
            goto end;
        }
    }

    if (!drbg->meth->instantiate(drbg, entropy, entropylen,
                         nonce, noncelen, pers, perslen)) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_INSTANTIATING_DRBG);
        goto end;
    }

    drbg->state = DRBG_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_prop_counter, drbg->reseed_next_counter);

 end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (nonce != NULL && drbg->cleanup_nonce != NULL)
        drbg->cleanup_nonce(drbg, nonce, noncelen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}

/*
 * Uninstantiate |drbg|. Must be instantiated before it can be used.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_uninstantiate(RAND_DRBG *drbg)
{
    if (drbg->meth == NULL) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_UNINSTANTIATE,
                RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        return 0;
    }

    /* Clear the entire drbg->ctr struct, then reset some important
     * members of the drbg->ctr struct (e.g. keysize, df_ks) to their
     * initial values.
     */
    drbg->meth->uninstantiate(drbg);
    return RAND_DRBG_set(drbg, drbg->type, drbg->flags);
}

/*
 * Reseed |drbg|, mixing in the specified data
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_reseed(RAND_DRBG *drbg,
                     const unsigned char *adin, size_t adinlen,
                     int prediction_resistance)
{
    unsigned char *entropy = NULL;
    size_t entropylen = 0;

    if (drbg->state == DRBG_ERROR) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_IN_ERROR_STATE);
        return 0;
    }
    if (drbg->state == DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_NOT_INSTANTIATED);
        return 0;
    }

    if (adin == NULL) {
        adinlen = 0;
    } else if (adinlen > drbg->max_adinlen) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    drbg->state = DRBG_ERROR;

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_prop_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if(!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    if (drbg->get_entropy != NULL)
        entropylen = drbg->get_entropy(drbg, &entropy, drbg->strength,
                                       drbg->min_entropylen,
                                       drbg->max_entropylen,
                                       prediction_resistance);
    if (entropylen < drbg->min_entropylen
            || entropylen > drbg->max_entropylen) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!drbg->meth->reseed(drbg, entropy, entropylen, adin, adinlen))
        goto end;

    drbg->state = DRBG_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_prop_counter, drbg->reseed_next_counter);

 end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}

/*
 * Restart |drbg|, using the specified entropy or additional input
 *
 * Tries its best to get the drbg instantiated by all means,
 * regardless of its current state.
 *
 * Optionally, a |buffer| of |len| random bytes can be passed,
 * which is assumed to contain at least |entropy| bits of entropy.
 *
 * If |entropy| > 0, the buffer content is used as entropy input.
 *
 * If |entropy| == 0, the buffer content is used as additional input
 *
 * Returns 1 on success, 0 on failure.
 *
 * This function is used internally only.
 */
int rand_drbg_restart(RAND_DRBG *drbg,
                      const unsigned char *buffer, size_t len, size_t entropy)
{
    int reseeded = 0;
    const unsigned char *adin = NULL;
    size_t adinlen = 0;

    if (drbg->seed_pool != NULL) {
        RANDerr(RAND_F_RAND_DRBG_RESTART, ERR_R_INTERNAL_ERROR);
        drbg->state = DRBG_ERROR;
        rand_pool_free(drbg->seed_pool);
        drbg->seed_pool = NULL;
        return 0;
    }

    if (buffer != NULL) {
        if (entropy > 0) {
            if (drbg->max_entropylen < len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART,
                    RAND_R_ENTROPY_INPUT_TOO_LONG);
                drbg->state = DRBG_ERROR;
                return 0;
            }

            if (entropy > 8 * len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART, RAND_R_ENTROPY_OUT_OF_RANGE);
                drbg->state = DRBG_ERROR;
                return 0;
            }

            /* will be picked up by the rand_drbg_get_entropy() callback */
            drbg->seed_pool = rand_pool_attach(buffer, len, entropy);
            if (drbg->seed_pool == NULL)
                return 0;
        } else {
            if (drbg->max_adinlen < len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART,
                        RAND_R_ADDITIONAL_INPUT_TOO_LONG);
                drbg->state = DRBG_ERROR;
                return 0;
            }
            adin = buffer;
            adinlen = len;
        }
    }

    /* repair error state */
    if (drbg->state == DRBG_ERROR)
        RAND_DRBG_uninstantiate(drbg);

    /* repair uninitialized state */
    if (drbg->state == DRBG_UNINITIALISED) {
        /* reinstantiate drbg */
        RAND_DRBG_instantiate(drbg,
                              (const unsigned char *) ossl_pers_string,
                              sizeof(ossl_pers_string) - 1);
        /* already reseeded. prevent second reseeding below */
        reseeded = (drbg->state == DRBG_READY);
    }

    /* refresh current state if entropy or additional input has been provided */
    if (drbg->state == DRBG_READY) {
        if (adin != NULL) {
            /*
             * mix in additional input without reseeding
             *
             * Similar to RAND_DRBG_reseed(), but the provided additional
             * data |adin| is mixed into the current state without pulling
             * entropy from the trusted entropy source using get_entropy().
             * This is not a reseeding in the strict sense of NIST SP 800-90A.
             */
            drbg->meth->reseed(drbg, adin, adinlen, NULL, 0);
        } else if (reseeded == 0) {
            /* do a full reseeding if it has not been done yet above */
            RAND_DRBG_reseed(drbg, NULL, 0, 0);
        }
    }

    rand_pool_free(drbg->seed_pool);
    drbg->seed_pool = NULL;

    return drbg->state == DRBG_READY;
}

/*
 * Generate |outlen| bytes into the buffer at |out|.  Reseed if we need
 * to or if |prediction_resistance| is set.  Additional input can be
 * sent in |adin| and |adinlen|.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success, 0 on failure.
 *
 */
int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen,
                       int prediction_resistance,
                       const unsigned char *adin, size_t adinlen)
{
    int reseed_required = 0;

    if (drbg->state != DRBG_READY) {
        /* try to recover from previous errors */
        rand_drbg_restart(drbg, NULL, 0, 0);

        if (drbg->state == DRBG_ERROR) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_IN_ERROR_STATE);
            return 0;
        }
        if (drbg->state == DRBG_UNINITIALISED) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_NOT_INSTANTIATED);
            return 0;
        }
    }

    if (outlen > drbg->max_request) {
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_REQUEST_TOO_LARGE_FOR_DRBG);
        return 0;
    }
    if (adinlen > drbg->max_adinlen) {
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    if (drbg->fork_count != rand_fork_count) {
        drbg->fork_count = rand_fork_count;
        reseed_required = 1;
    }

    if (drbg->reseed_interval > 0) {
        if (drbg->reseed_gen_counter >= drbg->reseed_interval)
            reseed_required = 1;
    }
    if (drbg->reseed_time_interval > 0) {
        time_t now = time(NULL);
        if (now < drbg->reseed_time
            || now - drbg->reseed_time >= drbg->reseed_time_interval)
            reseed_required = 1;
    }
    if (drbg->parent != NULL) {
        unsigned int reseed_counter = tsan_load(&drbg->reseed_prop_counter);
        if (reseed_counter > 0
                && tsan_load(&drbg->parent->reseed_prop_counter)
                   != reseed_counter)
            reseed_required = 1;
    }

    if (reseed_required || prediction_resistance) {
        if (!RAND_DRBG_reseed(drbg, adin, adinlen, prediction_resistance)) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_RESEED_ERROR);
            return 0;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!drbg->meth->generate(drbg, out, outlen, adin, adinlen)) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_GENERATE_ERROR);
        return 0;
    }

    drbg->reseed_gen_counter++;

    return 1;
}

/*
 * Generates |outlen| random bytes and stores them in |out|. It will
 * using the given |drbg| to generate the bytes.
 *
 * Requires that drbg->lock is already locked for write, if non-null.
 *
 * Returns 1 on success 0 on failure.
 */
int RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    unsigned char *additional = NULL;
    size_t additional_len;
    size_t chunk;
    size_t ret = 0;

    if (drbg->adin_pool == NULL) {
        if (drbg->type == 0)
            goto err;
        drbg->adin_pool = rand_pool_new(0, 0, drbg->max_adinlen);
        if (drbg->adin_pool == NULL)
            goto err;
    }

    additional_len = rand_drbg_get_additional_data(drbg->adin_pool,
                                                   &additional);

    for ( ; outlen > 0; outlen -= chunk, out += chunk) {
        chunk = outlen;
        if (chunk > drbg->max_request)
            chunk = drbg->max_request;
        ret = RAND_DRBG_generate(drbg, out, chunk, 0, additional, additional_len);
        if (!ret)
            goto err;
    }
    ret = 1;

 err:
    if (additional != NULL)
        rand_drbg_cleanup_additional_data(drbg->adin_pool, additional);

    return ret;
}

/*
 * Set the RAND_DRBG callbacks for obtaining entropy and nonce.
 *
 * Setting the callbacks is allowed only if the drbg has not been
 * initialized yet. Otherwise, the operation will fail.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_callbacks(RAND_DRBG *drbg,
                            RAND_DRBG_get_entropy_fn get_entropy,
                            RAND_DRBG_cleanup_entropy_fn cleanup_entropy,
                            RAND_DRBG_get_nonce_fn get_nonce,
                            RAND_DRBG_cleanup_nonce_fn cleanup_nonce)
{
    if (drbg->state != DRBG_UNINITIALISED
            || drbg->parent != NULL)
        return 0;
    drbg->get_entropy = get_entropy;
    drbg->cleanup_entropy = cleanup_entropy;
    drbg->get_nonce = get_nonce;
    drbg->cleanup_nonce = cleanup_nonce;
    return 1;
}

/*
 * Set the reseed interval.
 *
 * The drbg will reseed automatically whenever the number of generate
 * requests exceeds the given reseed interval. If the reseed interval
 * is 0, then this feature is disabled.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg, unsigned int interval)
{
    if (interval > MAX_RESEED_INTERVAL)
        return 0;
    drbg->reseed_interval = interval;
    return 1;
}

/*
 * Set the reseed time interval.
 *
 * The drbg will reseed automatically whenever the time elapsed since
 * the last reseeding exceeds the given reseed time interval. For safety,
 * a reseeding will also occur if the clock has been reset to a smaller
 * value.
 *
 * Returns 1 on success, 0 on failure.
 */
int RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg, time_t interval)
{
    if (interval > MAX_RESEED_TIME_INTERVAL)
        return 0;
    drbg->reseed_time_interval = interval;
    return 1;
}

/*
 * Set the default values for reseed (time) intervals of new DRBG instances
 *
 * The default values can be set independently for master DRBG instances
 * (without a parent) and slave DRBG instances (with parent).
 *
 * Returns 1 on success, 0 on failure.
 */

int RAND_DRBG_set_reseed_defaults(
                                  unsigned int _master_reseed_interval,
                                  unsigned int _slave_reseed_interval,
                                  time_t _master_reseed_time_interval,
                                  time_t _slave_reseed_time_interval
                                  )
{
    if (_master_reseed_interval > MAX_RESEED_INTERVAL
        || _slave_reseed_interval > MAX_RESEED_INTERVAL)
        return 0;

    if (_master_reseed_time_interval > MAX_RESEED_TIME_INTERVAL
        || _slave_reseed_time_interval > MAX_RESEED_TIME_INTERVAL)
        return 0;

    master_reseed_interval = _master_reseed_interval;
    slave_reseed_interval = _slave_reseed_interval;

    master_reseed_time_interval = _master_reseed_time_interval;
    slave_reseed_time_interval = _slave_reseed_time_interval;

    return 1;
}

/*
 * Locks the given drbg. Locking a drbg which does not have locking
 * enabled is considered a successful no-op.
 *
 * Returns 1 on success, 0 on failure.
 */
int rand_drbg_lock(RAND_DRBG *drbg)
{
    if (drbg->lock != NULL)
        return CRYPTO_THREAD_write_lock(drbg->lock);

    return 1;
}

/*
 * Unlocks the given drbg. Unlocking a drbg which does not have locking
 * enabled is considered a successful no-op.
 *
 * Returns 1 on success, 0 on failure.
 */
int rand_drbg_unlock(RAND_DRBG *drbg)
{
    if (drbg->lock != NULL)
        return CRYPTO_THREAD_unlock(drbg->lock);

    return 1;
}

/*
 * Enables locking for the given drbg
 *
 * Locking can only be enabled if the random generator
 * is in the uninitialized state.
 *
 * Returns 1 on success, 0 on failure.
 */
int rand_drbg_enable_locking(RAND_DRBG *drbg)
{
    if (drbg->state != DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_ENABLE_LOCKING,
                RAND_R_DRBG_ALREADY_INITIALIZED);
        return 0;
    }

    if (drbg->lock == NULL) {
        if (drbg->parent != NULL && drbg->parent->lock == NULL) {
            RANDerr(RAND_F_RAND_DRBG_ENABLE_LOCKING,
                    RAND_R_PARENT_LOCKING_NOT_ENABLED);
            return 0;
        }

        drbg->lock = CRYPTO_THREAD_lock_new();
        if (drbg->lock == NULL) {
            RANDerr(RAND_F_RAND_DRBG_ENABLE_LOCKING,
                    RAND_R_FAILED_TO_CREATE_LOCK);
            return 0;
        }
    }

    return 1;
}

/*
 * Get and set the EXDATA
 */
int RAND_DRBG_set_ex_data(RAND_DRBG *drbg, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&drbg->ex_data, idx, arg);
}

void *RAND_DRBG_get_ex_data(const RAND_DRBG *drbg, int idx)
{
    return CRYPTO_get_ex_data(&drbg->ex_data, idx);
}


/*
 * The following functions provide a RAND_METHOD that works on the
 * global DRBG.  They lock.
 */

/*
 * Allocates a new global DRBG on the secure heap (if enabled) and
 * initializes it with default settings.
 *
 * Returns a pointer to the new DRBG instance on success, NULL on failure.
 */
static RAND_DRBG *drbg_setup(RAND_DRBG *parent)
{
    RAND_DRBG *drbg;

    drbg = RAND_DRBG_secure_new(rand_drbg_type, rand_drbg_flags, parent);
    if (drbg == NULL)
        return NULL;

    /* Only the master DRBG needs to have a lock */
    if (parent == NULL && rand_drbg_enable_locking(drbg) == 0)
        goto err;

    /* enable seed propagation */
    tsan_store(&drbg->reseed_prop_counter, 1);

    /*
     * Ignore instantiation error to support just-in-time instantiation.
     *
     * The state of the drbg will be checked in RAND_DRBG_generate() and
     * an automatic recovery is attempted.
     */
    (void)RAND_DRBG_instantiate(drbg,
                                (const unsigned char *) ossl_pers_string,
                                sizeof(ossl_pers_string) - 1);
    return drbg;

err:
    RAND_DRBG_free(drbg);
    return NULL;
}

/*
 * Initialize the global DRBGs on first use.
 * Returns 1 on success, 0 on failure.
 */
DEFINE_RUN_ONCE_STATIC(do_rand_drbg_init)
{
    /*
     * ensure that libcrypto is initialized, otherwise the
     * DRBG locks are not cleaned up properly
     */
    if (!OPENSSL_init_crypto(0, NULL))
        return 0;

    if (!CRYPTO_THREAD_init_local(&private_drbg, NULL))
        return 0;

    if (!CRYPTO_THREAD_init_local(&public_drbg, NULL))
        goto err1;

    master_drbg = drbg_setup(NULL);
    if (master_drbg == NULL)
        goto err2;

    return 1;

err2:
    CRYPTO_THREAD_cleanup_local(&public_drbg);
err1:
    CRYPTO_THREAD_cleanup_local(&private_drbg);
    return 0;
}

/* Clean up the global DRBGs before exit */
void rand_drbg_cleanup_int(void)
{
    if (master_drbg != NULL) {
        RAND_DRBG_free(master_drbg);
        master_drbg = NULL;

        CRYPTO_THREAD_cleanup_local(&private_drbg);
        CRYPTO_THREAD_cleanup_local(&public_drbg);
    }
}

void drbg_delete_thread_state(void)
{
    RAND_DRBG *drbg;

    drbg = CRYPTO_THREAD_get_local(&public_drbg);
    CRYPTO_THREAD_set_local(&public_drbg, NULL);
    RAND_DRBG_free(drbg);

    drbg = CRYPTO_THREAD_get_local(&private_drbg);
    CRYPTO_THREAD_set_local(&private_drbg, NULL);
    RAND_DRBG_free(drbg);
}

/* Implements the default OpenSSL RAND_bytes() method */
static int drbg_bytes(unsigned char *out, int count)
{
    int ret;
    RAND_DRBG *drbg = RAND_DRBG_get0_public();

    if (drbg == NULL)
        return 0;

    ret = RAND_DRBG_bytes(drbg, out, count);

    return ret;
}

/*
 * Calculates the minimum length of a full entropy buffer
 * which is necessary to seed (i.e. instantiate) the DRBG
 * successfully.
 */
size_t rand_drbg_seedlen(RAND_DRBG *drbg)
{
    /*
     * If no os entropy source is available then RAND_seed(buffer, bufsize)
     * is expected to succeed if and only if the buffer length satisfies
     * the following requirements, which follow from the calculations
     * in RAND_DRBG_instantiate().
     */
    size_t min_entropy = drbg->strength;
    size_t min_entropylen = drbg->min_entropylen;

    /*
     * Extra entropy for the random nonce in the absence of a
     * get_nonce callback, see comment in RAND_DRBG_instantiate().
     */
    if (drbg->min_noncelen > 0 && drbg->get_nonce == NULL) {
        min_entropy += drbg->strength / 2;
        min_entropylen += drbg->min_noncelen;
    }

    /*
     * Convert entropy requirement from bits to bytes
     * (dividing by 8 without rounding upwards, because
     * all entropy requirements are divisible by 8).
     */
    min_entropy >>= 3;

    /* Return a value that satisfies both requirements */
    return min_entropy > min_entropylen ? min_entropy : min_entropylen;
}

/* Implements the default OpenSSL RAND_add() method */
static int drbg_add(const void *buf, int num, double randomness)
{
    int ret = 0;
    RAND_DRBG *drbg = RAND_DRBG_get0_master();
    size_t buflen;
    size_t seedlen;

    if (drbg == NULL)
        return 0;

    if (num < 0 || randomness < 0.0)
        return 0;

    rand_drbg_lock(drbg);
    seedlen = rand_drbg_seedlen(drbg);

    buflen = (size_t)num;

    if (buflen < seedlen || randomness < (double) seedlen) {
#if defined(OPENSSL_RAND_SEED_NONE)
        /*
         * If no os entropy source is available, a reseeding will fail
         * inevitably. So we use a trick to mix the buffer contents into
         * the DRBG state without forcing a reseeding: we generate a
         * dummy random byte, using the buffer content as additional data.
         * Note: This won't work with RAND_DRBG_FLAG_CTR_NO_DF.
         */
        unsigned char dummy[1];

        ret = RAND_DRBG_generate(drbg, dummy, sizeof(dummy), 0, buf, buflen);
        rand_drbg_unlock(drbg);
        return ret;
#else
        /*
         * If an os entropy source is avaible then we declare the buffer content
         * as additional data by setting randomness to zero and trigger a regular
         * reseeding.
         */
        randomness = 0.0;
#endif
    }


    if (randomness > (double)seedlen) {
        /*
         * The purpose of this check is to bound |randomness| by a
         * relatively small value in order to prevent an integer
         * overflow when multiplying by 8 in the rand_drbg_restart()
         * call below. Note that randomness is measured in bytes,
         * not bits, so this value corresponds to eight times the
         * security strength.
         */
        randomness = (double)seedlen;
    }

    ret = rand_drbg_restart(drbg, buf, buflen, (size_t)(8 * randomness));
    rand_drbg_unlock(drbg);

    return ret;
}

/* Implements the default OpenSSL RAND_seed() method */
static int drbg_seed(const void *buf, int num)
{
    return drbg_add(buf, num, num);
}

/* Implements the default OpenSSL RAND_status() method */
static int drbg_status(void)
{
    int ret;
    RAND_DRBG *drbg = RAND_DRBG_get0_master();

    if (drbg == NULL)
        return 0;

    rand_drbg_lock(drbg);
    ret = drbg->state == DRBG_READY ? 1 : 0;
    rand_drbg_unlock(drbg);
    return ret;
}

/*
 * Get the master DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 *
 */
RAND_DRBG *RAND_DRBG_get0_master(void)
{
    if (!RUN_ONCE(&rand_drbg_init, do_rand_drbg_init))
        return NULL;

    return master_drbg;
}

/*
 * Get the public DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *RAND_DRBG_get0_public(void)
{
    RAND_DRBG *drbg;

    if (!RUN_ONCE(&rand_drbg_init, do_rand_drbg_init))
        return NULL;

    drbg = CRYPTO_THREAD_get_local(&public_drbg);
    if (drbg == NULL) {
        if (!ossl_init_thread_start(OPENSSL_INIT_THREAD_RAND))
            return NULL;
        drbg = drbg_setup(master_drbg);
        CRYPTO_THREAD_set_local(&public_drbg, drbg);
    }
    return drbg;
}

/*
 * Get the private DRBG.
 * Returns pointer to the DRBG on success, NULL on failure.
 */
RAND_DRBG *RAND_DRBG_get0_private(void)
{
    RAND_DRBG *drbg;

    if (!RUN_ONCE(&rand_drbg_init, do_rand_drbg_init))
        return NULL;

    drbg = CRYPTO_THREAD_get_local(&private_drbg);
    if (drbg == NULL) {
        if (!ossl_init_thread_start(OPENSSL_INIT_THREAD_RAND))
            return NULL;
        drbg = drbg_setup(master_drbg);
        CRYPTO_THREAD_set_local(&private_drbg, drbg);
    }
    return drbg;
}

RAND_METHOD rand_meth = {
    drbg_seed,
    drbg_bytes,
    NULL,
    drbg_add,
    drbg_bytes,
    drbg_status
};

RAND_METHOD *RAND_OpenSSL(void)
{
    return &rand_meth;
}


#define GMold_MD_DIGEST_LENGTH        32
#define GMold_STATE_SIZE      1023
static size_t GMold_state_num = 0, GMold_state_index = 0;
static unsigned char GMold_state[GMold_STATE_SIZE + GMold_MD_DIGEST_LENGTH];
static unsigned char GMold_md[GMold_MD_DIGEST_LENGTH];
static long GMold_md_count[2] = { 0, 0 };

static double GMold_entropy = 0;
static int GMold_initialized = 0;

static CRYPTO_RWLOCK *GMold_rand_lock = NULL;
static CRYPTO_RWLOCK *GMold_rand_tmp_lock = NULL;
static CRYPTO_ONCE GMold_rand_lock_init = CRYPTO_ONCE_STATIC_INIT;
static unsigned int GMold_crypto_lock_rand = 0;
static CRYPTO_THREAD_ID GMold_locking_threadid;

static int GMold_rand_hw_seed(EVP_MD_CTX *ctx);
static void GMold_rand_cleanup(void);
static int GMold_rand_seed(const void *buf, int num);
static int GMold_rand_add(const void *buf, int num, double add_entropy);
static int GMold_rand_nopseudo_bytes(unsigned char *buf, int num);
static int GMold_rand_pseudo_bytes(unsigned char *buf, int num);
static int GMold_rand_status(void);

RAND_METHOD GMold_rand_meth = {
    GMold_rand_seed,
    GMold_rand_nopseudo_bytes,
    GMold_rand_cleanup,
    GMold_rand_add,
    GMold_rand_pseudo_bytes,
    GMold_rand_status
};

static int GMold_do_rand_lock_init(void);
static int GMold_do_rand_lock_init_ossl_ret_ = 0;
static void GMold_do_rand_lock_init_ossl_(void)
{
    GMold_do_rand_lock_init_ossl_ret_ = GMold_do_rand_lock_init();
}
static int GMold_do_rand_lock_init(void)
{
    OPENSSL_init_crypto(0, NULL);
    GMold_rand_lock = CRYPTO_THREAD_lock_new();
    GMold_rand_tmp_lock = CRYPTO_THREAD_lock_new();
    return GMold_rand_lock != NULL && GMold_rand_tmp_lock != NULL;
}

RAND_METHOD *GMold_RAND_OpenSSL(void)
{
    return (&GMold_rand_meth);
}

static void GMold_rand_cleanup(void)
{
    OPENSSL_cleanse(GMold_state, sizeof(GMold_state));
    GMold_state_num = 0;
    GMold_state_index = 0;
    OPENSSL_cleanse(GMold_md, GMold_MD_DIGEST_LENGTH);
    GMold_md_count[0] = 0;
    GMold_md_count[1] = 0;
    GMold_entropy = 0;
    GMold_initialized = 0;
    CRYPTO_THREAD_lock_free(GMold_rand_lock);
    CRYPTO_THREAD_lock_free(GMold_rand_tmp_lock);
}

static int GMold_rand_bytes(unsigned char *buf, int num, int pseudo)
{
    static volatile int stirred_pool = 0;
    int i, j, k;
    size_t num_ceil, st_idx, st_num;
    int ok;
    long md_c[2];
    unsigned char local_md[GMold_MD_DIGEST_LENGTH];
    EVP_MD_CTX *m;
#ifndef GETPID_IS_MEANINGLESS
    pid_t curr_pid = getpid();          //TODO xcst
#endif
    time_t curr_time = time(NULL);    //TODO xcst
    int do_stir_pool = 0;
/* time value for various platforms */
#ifdef OPENSSL_SYS_WIN32
    FILETIME tv;
# ifdef _WIN32_WCE
    SYSTEMTIME t;
    GetSystemTime(&t);
    SystemTimeToFileTime(&t, &tv);
# else
    GetSystemTimeAsFileTime(&tv);
# endif
#elif defined(OPENSSL_SYS_VXWORKS)
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &ts);
#elif defined(OPENSSL_SYS_DSPBIOS)
    unsigned long long tv, OPENSSL_rdtsc();
    tv = OPENSSL_rdtsc();
#else
    struct timeval tv;
    tv.tv_sec =0 ,tv.tv_usec = 0;
    gettimeofday(&tv, NULL);          //TODO xcst
#endif

#ifdef PREDICT
    if (rand_predictable) {
        static unsigned char val = 0;

        for (i = 0; i < num; i++)
            buf[i] = val++;
        return (1);
    }
#endif

    if (num <= 0)
        return 1;

    m = EVP_MD_CTX_new();
    if (m == NULL)
        goto err_mem;

    /* round upwards to multiple of MD_DIGEST_LENGTH/2 */
    num_ceil =
        (1 + (num - 1) / (GMold_MD_DIGEST_LENGTH / 2)) * (GMold_MD_DIGEST_LENGTH / 2);

    /*
     * (Based on the rand(3) manpage:)
     *
     * For each group of 10 bytes (or less), we do the following:
     *
     * Input into the hash function the local 'md' (which is initialized from
     * the global 'md' before any bytes are generated), the bytes that are to
     * be overwritten by the random bytes, and bytes from the 'state'
     * (incrementing looping index). From this digest output (which is kept
     * in 'md'), the top (up to) 10 bytes are returned to the caller and the
     * bottom 10 bytes are xored into the 'state'.
     *
     * Finally, after we have finished 'num' random bytes for the
     * caller, 'count' (which is incremented) and the local and global 'md'
     * are fed into the hash function and the results are kept in the
     * global 'md'.
     */

    if (!RUN_ONCE(&GMold_rand_lock_init, GMold_do_rand_lock_init))
        goto err_mem;

    CRYPTO_THREAD_write_lock(GMold_rand_lock);
    /*
     * We could end up in an async engine while holding this lock so ensure
     * we don't pause and cause a deadlock
     */
    GMold_ASYNC_block_pause();

    /* prevent rand_bytes() from trying to obtain the lock again */
    CRYPTO_THREAD_write_lock(GMold_rand_tmp_lock);
    GMold_locking_threadid = CRYPTO_THREAD_get_current_id();
    CRYPTO_THREAD_unlock(GMold_rand_tmp_lock);
    GMold_crypto_lock_rand = 1;

    if (!GMold_initialized) {
        GMold_RAND_poll();
        GMold_initialized = 1;
    }

    if (!stirred_pool)
        do_stir_pool = 1;

    ok = (GMold_entropy >= GMold_ENTROPY_NEEDED);
    if (!ok) {
        /*
         * If the PRNG state is not yet unpredictable, then seeing the PRNG
         * output may help attackers to determine the new state; thus we have
         * to decrease the entropy estimate. Once we've had enough initial
         * seeding we don't bother to adjust the entropy count, though,
         * because we're not ambitious to provide *information-theoretic*
         * randomness. NOTE: This approach fails if the program forks before
         * we have enough entropy. Entropy should be collected in a separate
         * input pool and be transferred to the output pool only when the
         * entropy limit has been reached.
         */
        GMold_entropy -= num;
        if (GMold_entropy < 0)
            GMold_entropy = 0;
    }

    if (do_stir_pool) {
        /*
         * In the output function only half of 'md' remains secret, so we
         * better make sure that the required entropy gets 'evenly
         * distributed' through 'state', our randomness pool. The input
         * function (rand_add) chains all of 'md', which makes it more
         * suitable for this purpose.
         */

        int n = GMold_STATE_SIZE;     /* so that the complete pool gets accessed */
        while (n > 0) {
#if GMold_MD_DIGEST_LENGTH > 32
# error "Please adjust DUMMY_SEED."
#endif
#define DUMMY_SEED "................................" /* at least MD_DIGEST_LENGTH */
            /*
             * Note that the seed does not matter, it's just that
             * rand_add expects to have something to hash.
             */
            GMold_rand_add(DUMMY_SEED, GMold_MD_DIGEST_LENGTH, 0.0);
            n -= GMold_MD_DIGEST_LENGTH;
        }
        if (ok)
            stirred_pool = 1;
    }

    st_idx = GMold_state_index;
    st_num = GMold_state_num;
    md_c[0] = GMold_md_count[0];
    md_c[1] = GMold_md_count[1];
    memcpy(local_md, GMold_md, sizeof GMold_md);
//    {
//        int gi = 0;
//        printf("rand bytes begin md =[");
//        for(gi=0; gi<GMold_MD_DIGEST_LENGTH; gi++){
//                printf("%02X-", GMold_md[gi]);
//        }
//        printf("]\n");
//    }         //TODO xcs test
    GMold_state_index += num_ceil;
    if (GMold_state_index > GMold_state_num)
        GMold_state_index %= GMold_state_num;

    /*
     * state[st_idx], ..., state[(st_idx + num_ceil - 1) % st_num] are now
     * ours (but other threads may use them too)
     */

    GMold_md_count[0] += 1;

    /* before unlocking, we must clear 'crypto_lock_rand' */
    GMold_crypto_lock_rand = 0;
    GMold_ASYNC_unblock_pause();
    CRYPTO_THREAD_unlock(GMold_rand_lock);

    while (num > 0) {
        /* num_ceil -= MD_DIGEST_LENGTH/2 */
        j = (num >= GMold_MD_DIGEST_LENGTH / 2) ? GMold_MD_DIGEST_LENGTH / 2 : num;
        num -= j;
        if (!EVP_DigestInit_ex(m,GMold_EVP_sm3(), NULL))
            goto err;
#ifndef GETPID_IS_MEANINGLESS
        if (curr_pid) {         /* just in the first iteration to save time */
            if (!GMold_EVP_DigestUpdate(m, (unsigned char *)&curr_pid, sizeof curr_pid))
                goto err;
            curr_pid = 0;
        }
#endif
        if (curr_time) {        /* just in the first iteration to save time */
            if (!GMold_EVP_DigestUpdate(m, (unsigned char *)&curr_time, sizeof curr_time))
                goto err;
            if (!GMold_EVP_DigestUpdate(m, (unsigned char *)&tv, sizeof tv))
                goto err;
            curr_time = 0;
            if (!GMold_rand_hw_seed(m))
                goto err;
        }
        if (!GMold_EVP_DigestUpdate(m, local_md, GMold_MD_DIGEST_LENGTH))
            goto err;
        if (!GMold_EVP_DigestUpdate(m, (unsigned char *)&(md_c[0]), sizeof(md_c)))
            goto err;

        k = (st_idx + GMold_MD_DIGEST_LENGTH / 2) - st_num;
        if (k > 0) {
            if (!GMold_EVP_DigestUpdate(m, &(GMold_state[st_idx]), GMold_MD_DIGEST_LENGTH / 2 - k))
                goto err;
            if (!GMold_EVP_DigestUpdate(m, &(GMold_state[0]), k))
                goto err;
        } else if (!GMold_EVP_DigestUpdate(m, &(GMold_state[st_idx]), GMold_MD_DIGEST_LENGTH / 2))
            goto err;
        if (!EVP_DigestFinal_ex(m, local_md,NULL))
            goto err;

        for (i = 0; i < GMold_MD_DIGEST_LENGTH / 2; i++) {
            /* may compete with other threads */
            GMold_state[st_idx++] ^= local_md[i];
            if (st_idx >= st_num)
                st_idx = 0;
            if (i < j)
                *(buf++) = local_md[i + GMold_MD_DIGEST_LENGTH / 2];
        }
    }

    if (!GMold_EVP_DigestInit_ex(m,GMold_EVP_sm3(), NULL)
        || !GMold_EVP_DigestUpdate(m, (unsigned char *)&(md_c[0]), sizeof(md_c))
        || !GMold_EVP_DigestUpdate(m, local_md, GMold_MD_DIGEST_LENGTH))
        goto err;
    CRYPTO_THREAD_write_lock(GMold_rand_lock);
    /*
     * Prevent deadlocks if we end up in an async engine
     */
    GMold_ASYNC_block_pause();
    if (!GMold_EVP_DigestUpdate(m, GMold_md, GMold_MD_DIGEST_LENGTH) || !EVP_DigestFinal_ex(m, GMold_md,NULL)) {
        CRYPTO_THREAD_unlock(GMold_rand_lock);
        goto err;
    }
//    {
//        int gi = 0;
//        printf("rand bytes end md =[");
//        for(gi=0; gi<GMold_MD_DIGEST_LENGTH; gi++){
//                printf("%02X-", GMold_md[gi]);
//        }
//        printf("]\n");
//    }         //TODO xcs test
    GMold_ASYNC_unblock_pause();
    CRYPTO_THREAD_unlock(GMold_rand_lock);

    EVP_MD_CTX_free(m);
    if (ok)
        return (1);
    else if (pseudo)
        return 0;
    else {
        ERR_add_error_data(1, "You need to read the OpenSSL FAQ, "
                           "https://www.openssl.org/docs/faq.html");
        return (0);
    }
 err:
    EVP_MD_CTX_free(m);
    return 0;
 err_mem:
    EVP_MD_CTX_free(m);
    return 0;

}


static int GMold_rand_seed(const void *buf, int num)
{
    return GMold_rand_add(buf, num, (double)num);
}

static int GMold_rand_add(const void *buf, int num, double add)
{
    int i, j, k, st_idx;
    long md_c[2];
    unsigned char local_md[GMold_MD_DIGEST_LENGTH];
    EVP_MD_CTX *m;
    int do_not_lock;
    int rv = 0;

    if (!num)
        return 1;

    /*
     * (Based on the rand(3) manpage)
     *
     * The input is chopped up into units of 20 bytes (or less for
     * the last block).  Each of these blocks is run through the hash
     * function as follows:  The data passed to the hash function
     * is the current 'md', the same number of bytes from the 'state'
     * (the location determined by in incremented looping index) as
     * the current 'block', the new key data 'block', and 'count'
     * (which is incremented after each use).
     * The result of this is kept in 'md' and also xored into the
     * 'state' at the same locations that were used as input into the
     * hash function.
     */

    m = EVP_MD_CTX_new();
    if (m == NULL)
        goto err;

    if (!RUN_ONCE(&GMold_rand_lock_init, GMold_do_rand_lock_init))
        goto err;

    /* check if we already have the lock */
    if (GMold_crypto_lock_rand) {
        CRYPTO_THREAD_ID cur = CRYPTO_THREAD_get_current_id();
        CRYPTO_THREAD_read_lock(GMold_rand_tmp_lock);
        do_not_lock = CRYPTO_THREAD_compare_id(GMold_locking_threadid, cur);
        CRYPTO_THREAD_unlock(GMold_rand_tmp_lock);
    } else
        do_not_lock = 0;

    if (!do_not_lock)
        CRYPTO_THREAD_write_lock(GMold_rand_lock);
    st_idx = GMold_state_index;

    /*
     * use our own copies of the counters so that even if a concurrent thread
     * seeds with exactly the same data and uses the same subarray there's
     * _some_ difference
     */
    md_c[0] = GMold_md_count[0];
    md_c[1] = GMold_md_count[1];
//    {
//        int gi = 0;
//        printf("rand add begin md =[");
//        for(gi=0; gi<GMold_MD_DIGEST_LENGTH; gi++){
//                printf("%02X-", GMold_md[gi]);
//        }
//        printf("]\n");
//    }             //TODO xcs test
    memcpy(local_md, GMold_md, sizeof(GMold_md));

    /* state_index <= state_num <= STATE_SIZE */
    GMold_state_index += num;
    if (GMold_state_index >= GMold_STATE_SIZE) {
        GMold_state_index %= GMold_STATE_SIZE;
        GMold_state_num = GMold_STATE_SIZE;
    } else if (GMold_state_num < GMold_STATE_SIZE) {
        if (GMold_state_index > GMold_state_num)
            GMold_state_num = GMold_state_index;
    }
    /* GMold_state_index <= GMold_state_num <= GMold_STATE_SIZE */

    /*
     * state[st_idx], ..., state[(st_idx + num - 1) % STATE_SIZE] are what we
     * will use now, but other threads may use them as well
     */

    GMold_md_count[1] += (num / GMold_MD_DIGEST_LENGTH) + (num % GMold_MD_DIGEST_LENGTH > 0);

    if (!do_not_lock)
        CRYPTO_THREAD_unlock(GMold_rand_lock);

    for (i = 0; i < num; i += GMold_MD_DIGEST_LENGTH) {
        j = (num - i);
        j = (j > GMold_MD_DIGEST_LENGTH) ? GMold_MD_DIGEST_LENGTH : j;

        if (!GMold_EVP_DigestInit_ex(m,GMold_EVP_sm3(), NULL))
            goto err;
        if (!GMold_EVP_DigestUpdate(m, local_md, GMold_MD_DIGEST_LENGTH))
            goto err;
        k = (st_idx + j) - GMold_STATE_SIZE;
        if (k > 0) {
            if (!GMold_EVP_DigestUpdate(m, &(GMold_state[st_idx]), j - k))
                goto err;
            if (!GMold_EVP_DigestUpdate(m, &(GMold_state[0]), k))
                goto err;
        } else if (!GMold_EVP_DigestUpdate(m, &(GMold_state[st_idx]), j))
            goto err;

        /* DO NOT REMOVE THE FOLLOWING CALL TO MD_Update()! */
        if (!GMold_EVP_DigestUpdate(m, buf, j))
            goto err;
        /*
         * We know that line may cause programs such as purify and valgrind
         * to complain about use of uninitialized data.  The problem is not,
         * it's with the caller.  Removing that line will make sure you get
         * really bad randomness and thereby other problems such as very
         * insecure keys.
         */

        if (!GMold_EVP_DigestUpdate(m, (unsigned char *)&(md_c[0]), sizeof(md_c)))
            goto err;
        if (!EVP_DigestFinal_ex(m, local_md,NULL))
            goto err;
        md_c[1]++;

        buf = (const char *)buf + j;

        for (k = 0; k < j; k++) {
            /*
             * Parallel threads may interfere with this, but always each byte
             * of the new state is the XOR of some previous value of its and
             * local_md (intermediate values may be lost). Alway using locking
             * could hurt performance more than necessary given that
             * conflicts occur only when the total seeding is longer than the
             * random state.
             */
            GMold_state[st_idx++] ^= local_md[k];
            if (st_idx >= GMold_STATE_SIZE)
                st_idx = 0;
        }
    }

    if (!do_not_lock)
        CRYPTO_THREAD_write_lock(GMold_rand_lock);
    /*
     * Don't just copy back local_md into md -- this could mean that other
     * thread's seeding remains without effect (except for the incremented
     * counter).  By XORing it we keep at least as much entropy as fits into
     * md.
     */
    for (k = 0; k < (int)sizeof(GMold_md); k++) {
        GMold_md[k] ^= local_md[k];
    }
//    {
//        int gi = 0;
//        printf("rand add end md =[");
//        for(gi=0; gi<GMold_MD_DIGEST_LENGTH; gi++){
//                printf("%02X-", GMold_md[gi]);
//        }
//        printf("]\n");
//    }     //TODO xcs test
    if (GMold_entropy < GMold_ENTROPY_NEEDED) /* stop counting when we have enough */
        GMold_entropy += add;
    if (!do_not_lock)
        CRYPTO_THREAD_unlock(GMold_rand_lock);

    rv = 1;
 err:
    EVP_MD_CTX_free(m);
    return rv;
}

static int GMold_rand_nopseudo_bytes(unsigned char *buf, int num)
{
    return GMold_rand_bytes(buf, num, 0);
}

static int GMold_rand_pseudo_bytes(unsigned char *buf, int num)
{
    return GMold_rand_bytes(buf, num, 1);
}

static int GMold_rand_status(void)
{
    CRYPTO_THREAD_ID cur;
    int ret;
    int do_not_lock;

    if (!RUN_ONCE(&GMold_rand_lock_init, GMold_do_rand_lock_init))
        return 0;

    cur = CRYPTO_THREAD_get_current_id();
    /*
     * check if we already have the lock (could happen if a RAND_poll()
     * implementation calls RAND_status())
     */
    if (GMold_crypto_lock_rand) {
        CRYPTO_THREAD_read_lock(GMold_rand_tmp_lock);
        do_not_lock = CRYPTO_THREAD_compare_id(GMold_locking_threadid, cur);
        CRYPTO_THREAD_unlock(GMold_rand_tmp_lock);
    } else
        do_not_lock = 0;

    if (!do_not_lock) {
        CRYPTO_THREAD_write_lock(GMold_rand_lock);
        /*
         * Prevent deadlocks in case we end up in an async engine
         */
        GMold_ASYNC_block_pause();

        /*
         * prevent rand_bytes() from trying to obtain the lock again
         */
        CRYPTO_THREAD_write_lock(GMold_rand_tmp_lock);
        GMold_locking_threadid = cur;
        CRYPTO_THREAD_unlock(GMold_rand_tmp_lock);
        GMold_crypto_lock_rand = 1;
    }

    if (!GMold_initialized) {
        RAND_poll();
        GMold_initialized = 1;
    }

    ret = GMold_entropy >= GMold_ENTROPY_NEEDED;

    if (!do_not_lock) {
        /* before unlocking, we must clear 'crypto_lock_rand' */
        GMold_crypto_lock_rand = 0;

        GMold_ASYNC_unblock_pause();
        CRYPTO_THREAD_unlock(GMold_rand_lock);
    }

    return ret;
}


# define GMold_RDRAND_CALLS    4

//size_t OPENSSL_ia32_rdrand(void);
//extern unsigned int OPENSSL_ia32cap_P[];

//static int GMold_rand_hw_seed(EVP_MD_CTX *ctx)
//{
//    int i;
//    if (!(OPENSSL_ia32cap_P[1] & (1 << (62 - 32))))
//        return 1;
//    for (i = 0; i < GMold_RDRAND_CALLS; i++) {
//        size_t rnd;
//        rnd = OPENSSL_ia32_rdrand();
//        if (rnd == 0)
//            return 1;
//        if (!EVP_DigestUpdate(ctx, (unsigned char *)&rnd, sizeof(size_t)))
//            return 0;
//    }
//    return 1;
//}

///* XOR an existing buffer with random data */

//void GMold_rand_hw_xor(unsigned char *buf, size_t num)
//{
//    size_t rnd;
//    if (!(OPENSSL_ia32cap_P[1] & (1 << (62 - 32))))
//        return;
//    while (num >= sizeof(size_t)) {
//        rnd = OPENSSL_ia32_rdrand();
//        if (rnd == 0)
//            return;
//        *((size_t *)buf) ^= rnd;
//        buf += sizeof(size_t);
//        num -= sizeof(size_t);
//    }
//    if (num) {
//        rnd = OPENSSL_ia32_rdrand();
//        if (rnd == 0)
//            return;
//        while (num) {
//            *buf ^= rnd & 0xff;
//            rnd >>= 8;
//            buf++;
//            num--;
//        }
//    }
//}

static int GMold_rand_hw_seed(EVP_MD_CTX *ctx)
{
    int i;
//    if (!(OPENSSL_ia32cap_P[1] & (1 << (62 - 32))))
//        return 1;
//    for (i = 0; i < GMold_RDRAND_CALLS; i++) {
//        size_t rnd;
//        rnd = 1000;//OPENSSL_ia32_rdrand();      //TODO xcst
//        if (rnd == 0)
//            return 1;
//        if (!GMold_EVP_DigestUpdate(ctx, (unsigned char *)&rnd, sizeof(size_t)))
//            return 0;
//    }
    return 1;
}

void GMold_rand_hw_xor(unsigned char *buf, size_t num)
{
    return;     //TODO xcs
}
