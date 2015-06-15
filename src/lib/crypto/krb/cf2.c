/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/krb/cf2.c */
/*
 * Copyright (C) 2009 by the Massachusetts Institute of Technology.
 * All rights reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * Implement KRB_FX_CF2 function per draft-ietf-krb-wg-preauth-framework-09.
 * Take two keys and two pepper strings as input and return a combined key.
 */

#include "crypto_int.h"

krb5_error_code KRB5_CALLCONV
krb5_c_prf_plus(krb5_context context, const krb5_keyblock *k,
                const krb5_data *input, krb5_data *output)
{
    char ibuf[input->length + 1];
    krb5_data in = { 0, sizeof(ibuf), ibuf };
    krb5_error_code retval = 0;
    size_t prflen = 0;

    retval = krb5_c_prf_length(context, k->enctype, &prflen);
    if (retval)
        return retval;

    if (output->length > 254 * prflen)
        return E2BIG; /* FIXME */

    memcpy(&in.data[1], input->data, input->length);
    for (size_t i = 0; i < (output->length + prflen - 1) / prflen; i++) {
        char obuf[prflen];
        krb5_data out = { 0, sizeof(obuf), obuf };

        in.data[0] = i + 1;
        retval = krb5_c_prf(context, k, &in, &out);
        if (retval)
            return retval;

        memcpy(&output->data[i * prflen], out.data,
               MIN(prflen, output->length - i * prflen));
    }

    return retval;
}

static krb5_error_code
data2key(krb5_context context, krb5_enctype enctype, const krb5_data *input,
         krb5_keyblock **output)
{
    const struct krb5_keytypes *etype = NULL;
    krb5_error_code retval = 0;

    if (!krb5_c_valid_enctype(enctype))
        return KRB5_BAD_ENCTYPE;

    etype = find_enctype(enctype);
    assert(etype != NULL);

    if (etype->enc->keybytes != input->length)
        return EMSGSIZE; /* FIXME */

    retval = krb5int_c_init_keyblock(context, enctype,
                                     etype->enc->keylength, output);
    if (retval != 0)
        return retval;

    retval = (*etype->rand2key)(input, *output);
    if (retval != 0)
        krb5int_c_free_keyblock(context, *output);

    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_c_derive(krb5_context context, const krb5_keyblock *k,
              const krb5_data *input, krb5_keyblock **output)
{
    char buf[k->length];
    krb5_data out = { 0, sizeof(buf), buf };
    krb5_error_code retval = 0;

    retval = krb5_c_prf_plus(context, k, input, &out);
    if (retval != 0)
        return retval;

    return data2key(context, k->enctype, &out, output);
}

krb5_error_code KRB5_CALLCONV
krb5_c_fx_cf2_simple(krb5_context context,
                     const krb5_keyblock *k1, const char *pepper1,
                     const krb5_keyblock *k2, const char *pepper2,
                     krb5_keyblock **out)
{
    const krb5_data p1 = { 0, strlen(pepper1), (char *) pepper1 };
    const krb5_data p2 = { 0, strlen(pepper2), (char *) pepper2 };
    char prfb1[k1->length];
    char prfb2[k1->length];
    krb5_data prf1 = { 0, sizeof(prfb1), prfb1 };
    krb5_data prf2 = { 0, sizeof(prfb1), prfb2 };
    krb5_error_code retval = 0;

    retval = krb5_c_prf_plus(context, k1, &p1, &prf1);
    if (retval)
        return retval;

    retval = krb5_c_prf_plus(context, k2, &p2, &prf2);
    if (retval)
        return retval;

    for (size_t i = 0; i < prf1.length; i++)
        prf1.data[i] ^= prf2.data[i];

    return data2key(context, k1->enctype, &prf1, out);
}
