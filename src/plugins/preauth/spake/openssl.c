/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/openssl.c - SPAKE implementations using OpenSSL */
/*
 * Copyright (C) 2015 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "k5-int.h"

#include "openssl.h"
#include "iana.h"

#ifdef SPAKE_OPENSSL
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

struct groupdata_st {
    const groupdef *gdef;
    EC_GROUP *group;
    BIGNUM *order;
    BN_CTX *ctx;
    EC_POINT *M;
    EC_POINT *N;
};

static void
openssl_fini(groupdata *gd)
{
    if (gd == NULL)
        return;

    EC_GROUP_free(gd->group);
    EC_POINT_free(gd->M);
    EC_POINT_free(gd->N);
    BN_CTX_free(gd->ctx);
    BN_free(gd->order);
}

static krb5_error_code
openssl_init(krb5_context context, const groupdef *gdef, groupdata **gdata_out)
{
    const spake_iana *reg = NULL;
    groupdata *gd;
    int nid;

    switch (gdef->id) {
    case SPAKE_GROUP_P256: nid = NID_X9_62_prime256v1; break;
    case SPAKE_GROUP_P384: nid = NID_secp384r1;        break;
    case SPAKE_GROUP_P521: nid = NID_secp521r1;        break;
    default: return ENOTSUP;
    };

    reg = &spake_iana_reg[gdef->id];

    gd = calloc(1, sizeof(*gd));
    if (gd == NULL)
        return ENOMEM;
    gd->gdef = gdef;

    gd->group = EC_GROUP_new_by_curve_name(nid);
    if (gd->group == NULL)
        goto error;

    gd->ctx = BN_CTX_new();
    if (gd->ctx == NULL)
        goto error;

    gd->order = BN_new();
    if (gd->order == NULL)
        goto error;
    if (!EC_GROUP_get_order(gd->group, gd->order, gd->ctx))
        goto error;

    gd->M = EC_POINT_new(gd->group);
    if (gd->M == NULL)
        goto error;
    if (!EC_POINT_oct2point(gd->group, gd->M, reg->m, reg->elem_len, gd->ctx))
        goto error;

    gd->N = EC_POINT_new(gd->group);
    if (gd->N == NULL)
        goto error;
    if (!EC_POINT_oct2point(gd->group, gd->N, reg->n, reg->elem_len, gd->ctx))
        goto error;

    *gdata_out = gd;
    return 0;

error:
    openssl_fini(gd);
    return ENOMEM;
}

/* Convert pseudo-random bytes into a scalar value in constant time.
 * Return NULL on failure. */
static inline BIGNUM *
unmarshal_w(const groupdata *gdata, const uint8_t *wbytes)
{
    const spake_iana *reg = &spake_iana_reg[gdata->gdef->id];
    BIGNUM *w = NULL;

    w = BN_new();
    if (!w)
        return NULL;

    BN_set_flags(w, BN_FLG_CONSTTIME);

    if (BN_bin2bn(wbytes, reg->mult_len, w) &&
        BN_div(NULL, w, w, gdata->order, gdata->ctx))
        return w;

    BN_free(w);
    return NULL;
}

static krb5_error_code
openssl_keygen(krb5_context context, groupdata *gdata, const uint8_t *wbytes,
               krb5_boolean use_m, uint8_t *prv_out, uint8_t *pub_out)
{
    const spake_iana *reg = &spake_iana_reg[gdata->gdef->id];
    const EC_POINT *constant = use_m ? gdata->M : gdata->N;
    krb5_boolean success = FALSE;
    EC_POINT *pub = NULL;
    BIGNUM *prv = NULL;
    BIGNUM *w = NULL;

    w = unmarshal_w(gdata, wbytes);
    if (!w)
        goto cleanup;

    pub = EC_POINT_new(gdata->group);
    if (pub == NULL)
        goto cleanup;

    prv = BN_new();
    if (prv == NULL)
        goto cleanup;

    if (!BN_rand_range(prv, gdata->order))
        goto cleanup;

    /* Compute prv*G + w*constant; EC_POINT_mul() does this in one call. */
    if (!EC_POINT_mul(gdata->group, pub, prv, constant, w, gdata->ctx))
        goto cleanup;

    /* Marshal prv into prv_out. */
    memset(prv_out, 0, reg->mult_len);
    BN_bn2bin(prv, &prv_out[reg->mult_len - BN_num_bytes(prv)]);

    /* Marshal pub into pub_out. */
    if (EC_POINT_point2oct(gdata->group, pub, POINT_CONVERSION_COMPRESSED,
                           pub_out, reg->elem_len, gdata->ctx)
            != reg->elem_len)
        goto cleanup;

    success = TRUE;

cleanup:
    EC_POINT_free(pub);
    BN_clear_free(prv);
    BN_clear_free(w);
    return success ? 0 : ENOMEM;
}

static krb5_error_code
openssl_result(krb5_context context, groupdata *gdata, const uint8_t *wbytes,
               const uint8_t *ourprv, const uint8_t *theirpub,
               krb5_boolean use_m, uint8_t *elem_out)
{
    const spake_iana *reg = &spake_iana_reg[gdata->gdef->id];
    const EC_POINT *constant = use_m ? gdata->M : gdata->N;
    krb5_boolean success = FALSE;
    krb5_boolean invalid = FALSE;
    EC_POINT *result = NULL;
    EC_POINT *pub = NULL;
    BIGNUM *priv = NULL;
    BIGNUM *w = NULL;

    w = unmarshal_w(gdata, wbytes);
    if (w == NULL)
        goto cleanup;

    priv = BN_bin2bn(ourprv, reg->mult_len, NULL);
    if (priv == NULL)
        goto cleanup;

    pub = EC_POINT_new(gdata->group);
    if (pub == NULL)
        goto cleanup;
    if (!EC_POINT_oct2point(gdata->group, pub, theirpub,
                            reg->elem_len, gdata->ctx)) {
        invalid = TRUE;
        goto cleanup;
    }

    /* Compute result = priv*(pub - w*constant), using result to hold the
     * intermediate steps. */
    result = EC_POINT_new(gdata->group);
    if (result == NULL)
        goto cleanup;
    if (!EC_POINT_mul(gdata->group, result, NULL, constant, w, gdata->ctx))
        goto cleanup;
    if (!EC_POINT_invert(gdata->group, result, gdata->ctx))
        goto cleanup;
    if (!EC_POINT_add(gdata->group, result, pub, result, gdata->ctx))
        goto cleanup;
    if (!EC_POINT_mul(gdata->group, result, NULL, result, priv, gdata->ctx))
        goto cleanup;

    /* Marshal result into elem_out. */
    if (EC_POINT_point2oct(gdata->group, result, POINT_CONVERSION_COMPRESSED,
                           elem_out, reg->elem_len, gdata->ctx)
            != reg->elem_len)
        goto cleanup;

    success = TRUE;

cleanup:
    BN_clear_free(priv);
    BN_clear_free(w);
    EC_POINT_free(pub);
    EC_POINT_free(result);
    return invalid ? EINVAL : (success ? 0 : ENOMEM);
}

groupdef openssl_P256 = {
    .id = SPAKE_GROUP_P256,
    .init = openssl_init,
    .keygen = openssl_keygen,
    .result = openssl_result,
    .fini = openssl_fini,
};

groupdef openssl_P384 = {
    .id = SPAKE_GROUP_P384,
    .init = openssl_init,
    .keygen = openssl_keygen,
    .result = openssl_result,
    .fini = openssl_fini,
};

groupdef openssl_P521 = {
    .id = SPAKE_GROUP_P521,
    .init = openssl_init,
    .keygen = openssl_keygen,
    .result = openssl_result,
    .fini = openssl_fini,
};
#endif /* SPAKE_OPENSSL */
