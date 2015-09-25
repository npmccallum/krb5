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
#include "internal.h"

#ifdef SPAKE_OPENSSL
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

typedef struct odata_st {
    const groupdef *gdef;
    BN_CTX *ctx;
    EC_GROUP *group;
    BIGNUM *order;
    EC_POINT *M;
    EC_POINT *N;
} odata;

static odata *
create_odata(int nid, uint8_t *M, uint8_t *N, const groupdef *gdef)
{
    odata *od;

    od = calloc(1, sizeof(*od));
    if (od == NULL)
        return NULL;
    od->gdef = gdef;

    od->ctx = BN_CTX_new();
    if (od->ctx == NULL)
        goto error;

    od->group = EC_GROUP_new_by_curve_name(nid);
    if (od->group == NULL)
        goto error;

    od->order = BN_new();
    if (od->order == NULL)
        goto error;
    if (!EC_GROUP_get_order(od->group, od->order, od->ctx))
        goto error;

    od->M = EC_POINT_new(od->group);
    if (od->M == NULL)
        goto error;
    if (!EC_POINT_oct2point(od->group, od->M, M, gdef->elem_len, od->ctx))
        goto error;

    od->N = EC_POINT_new(od->group);
    if (od->N == NULL)
        goto error;
    if (!EC_POINT_oct2point(od->group, od->N, N, gdef->elem_len, od->ctx))
        goto error;

    return od;

error:
    ossl_free(od);
    return NULL;
}

krb5_error_code
p256_init(krb5_context context, const groupdef *gdef, void **gdata_out)
{
    *gdata_out = create_odata(NID_X9_62_prime256v1, P256_M, P256_N, gdef);
    return (*gdata_out == NULL) ? ENOMEM : 0;
}

/* Convert pseudo-random bytes into a scalar value according to the spec.
 * Return NULL on failure. */
static BIGNUM *
unmarshal_w(const groupdef *gdef, const uint8_t *wbytes)
{
    BIGNUM *w;

    /*
     * P-256 requires no sanitization.  Other curves might require clearing
     * some of the high bits (e.g. P-521 would require clearing the high seven
     * bits).
     */

    w = BN_new();
    if (w == NULL)
        return NULL;
    if (!BN_bin2bn(wbytes, gdef->scalar_len, w)) {
        BN_clear_free(w);
        return NULL;
    }
    return w;
}

krb5_error_code
ossl_keygen(krb5_context context, void *gdata, const uint8_t *wbytes,
            krb5_boolean use_m, uint8_t *priv_out, uint8_t *pub_out)
{
    odata *od = gdata;
    const groupdef *gdef = od->gdef;
    EC_GROUP *group = od->group;
    BN_CTX *ctx = od->ctx;
    EC_POINT *pub = NULL, *constant;
    BIGNUM *priv = NULL, *w = NULL;
    krb5_boolean success = FALSE;
    size_t len;

    priv = BN_new();
    if (priv == NULL)
        goto cleanup;
    if (!BN_rand_range(priv, od->order))
        goto cleanup;

    w = unmarshal_w(gdef, wbytes);
    if (w == NULL)
        goto cleanup;

    /* Compute priv*G + w*constant; EC_POINT_mul() does this in one call. */
    pub = EC_POINT_new(group);
    if (pub == NULL)
        goto cleanup;
    constant = use_m ? od->M : od->N;
    if (!EC_POINT_mul(group, pub, priv, constant, w, ctx))
        goto cleanup;

    /* Marshal priv into priv_out. */
    memset(priv_out, 0, gdef->scalar_len);
    BN_bn2bin(priv, priv_out + gdef->scalar_len - BN_num_bytes(priv));

    /* Marshal pub into pub_out. */
    len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_COMPRESSED, pub_out,
                             gdef->elem_len, ctx);
    if (len != gdef->elem_len)
        goto cleanup;

    success = TRUE;

cleanup:
    BN_clear_free(priv);
    BN_clear_free(w);
    EC_POINT_free(pub);
    return success ? 0 : ENOMEM;
}

krb5_error_code
ossl_result(krb5_context context, void *gdata, const uint8_t *wbytes,
            const uint8_t *ourpriv, const uint8_t *theirpub,
            krb5_boolean use_m, uint8_t *elem_out)
{
    odata *od = gdata;
    const groupdef *gdef = od->gdef;
    EC_GROUP *group = od->group;
    BN_CTX *ctx = od->ctx;
    EC_POINT *pub = NULL, *result = NULL, *constant;
    BIGNUM *priv = NULL, *w = NULL;
    krb5_boolean success = FALSE, invalid = FALSE;
    size_t len;

    w = unmarshal_w(gdef, wbytes);
    if (w == NULL)
        goto cleanup;

    priv = BN_bin2bn(ourpriv, gdef->scalar_len, NULL);
    if (priv == NULL)
        goto cleanup;

    pub = EC_POINT_new(group);
    if (pub == NULL)
        goto cleanup;
    if (!EC_POINT_oct2point(group, pub, theirpub, gdef->elem_len, ctx)) {
        invalid = TRUE;
        goto cleanup;
    }

    /* Compute result = priv*(pub - w*constant), using result to hold the
     * intermediate steps. */
    result = EC_POINT_new(group);
    if (result == NULL)
        goto cleanup;
    constant = use_m ? od->M : od->N;
    if (!EC_POINT_mul(group, result, NULL, constant, w, ctx))
        goto cleanup;
    if (!EC_POINT_invert(group, result, ctx))
        goto cleanup;
    if (!EC_POINT_add(group, result, pub, result, ctx))
        goto cleanup;
    if (!EC_POINT_mul(group, result, NULL, result, priv, ctx))
        goto cleanup;

    /* Marshal result into elem_out. */
    len = EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED,
                             elem_out, gdef->elem_len, ctx);
    if (len != gdef->elem_len)
        goto cleanup;

    success = TRUE;

cleanup:
    BN_clear_free(priv);
    BN_clear_free(w);
    EC_POINT_free(pub);
    EC_POINT_free(result);
    return invalid ? EINVAL : (success ? 0 : ENOMEM);
}

void
ossl_free(void *gdata)
{
    odata *od = gdata;

    if (od == NULL)
        return;
    EC_POINT_free(od->M);
    EC_POINT_free(od->N);
    EC_GROUP_free(od->group);
    BN_CTX_free(od->ctx);
}

#endif /* SPAKE_OPENSSL */
