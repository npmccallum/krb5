/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/krb/auth_ind.c */
/*
 * Copyright 2016 by Red Hat, Inc.
 * All Rights Reserved.
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

#include "k5-int.h"

static krb5_error_code
unwrap_cammac(krb5_context ctx, krb5_authdata *ad, krb5_keyblock *tktkey,
              krb5_authdata ***adata)
{
    krb5_data *der_elements, ad_data = make_data(ad->contents, ad->length);
    krb5_error_code retval;
    krb5_cammac *cammac;
    krb5_boolean valid;

    retval = decode_krb5_cammac(&ad_data, &cammac);
    if (retval != 0)
        goto error;

    if (cammac->svc_verifier == NULL) {
        retval = EINVAL; /* FIXME: What is the correct error code? */
        goto error;
    }

    retval = encode_krb5_authdata(cammac->elements, &der_elements);
    if (retval != 0)
        goto error;

    retval = krb5_c_verify_checksum(ctx, tktkey, KRB5_KEYUSAGE_CAMMAC,
               der_elements, &cammac->svc_verifier->checksum, &valid);
    krb5_free_data(ctx, der_elements);
    if (retval != 0)
        goto error;
    if (!valid) {
        retval = EINVAL; /* FIXME: What is the correct error code? */
        goto error;
    }

    *adata = cammac->elements;
    cammac->elements = NULL;

    k5_free_cammac(ctx, cammac);
    return 0;

error:
    k5_free_cammac(ctx, cammac);
    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_auth_ind_decode(krb5_context ctx, const krb5_enc_tkt_part *tkt,
                     char ***auth_inds)
{
    krb5_authdata **adata = NULL;
    krb5_error_code retval = 0;
    krb5_data **strs = NULL;
    krb5_data data = {};
    size_t count = 1;
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;

    *auth_inds = calloc(count, sizeof(char *));
    if (*auth_inds == NULL)
        return ENOMEM;

    for (i = 0; tkt->authorization_data[i] != NULL; i++) {
        if (tkt->authorization_data[i]->ad_type != KRB5_AUTHDATA_CAMMAC)
            continue;

        retval = unwrap_cammac(ctx, tkt->authorization_data[i],
                               tkt->session, &adata);
        if (retval != 0)
            goto error;

        for (j = 0; adata[j] != NULL; j++) {
            data = make_data(adata[j]->contents, adata[j]->length);

            if (adata[j]->ad_type != KRB5_AUTHDATA_AUTH_INDICATOR)
                continue;

            if (decode_utf8_strings(&data, &strs) != 0) {
                retval = EINVAL;
                goto error;
            }

            for (k = 0; strs[k] != NULL; k++) {
                char **tmp;

                tmp = realloc(*auth_inds, ++count * sizeof(char *));
                if (tmp == NULL) {
                    retval = ENOMEM;
                    goto error;
                }
                *auth_inds = tmp;

                tmp[count - 1] = NULL;
                tmp[count - 2] = strndup(strs[k]->data, strs[k]->length);
                if (tmp[count - 2] == NULL) {
                    retval = ENOMEM;
                    goto error;
                }
            }

            k5_free_data_ptr_list(strs);
            strs = NULL;
        }

        krb5_free_authdata(ctx, adata);
        adata = NULL;
    }

error:
    krb5_free_authdata(ctx, adata);
    k5_free_data_ptr_list(strs);

    if (retval != 0) {
        for (i = 0; (*auth_inds)[i] != NULL; i++)
            free((*auth_inds)[i]);
        free(*auth_inds);
    }

    return retval;
}
