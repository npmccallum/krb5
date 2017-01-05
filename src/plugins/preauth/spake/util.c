/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/util.c - Utility functions for SPAKE preauth module */
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
#include "trace.h"
#include "util.h"

/* Use data to construct a single-element pa-data list of type
 * KRB5_PADATA_SPAKE.  Claim data's memory on success or failure. */
krb5_error_code
convert_to_padata(krb5_data *data, krb5_pa_data ***pa_out)
{
    krb5_pa_data *pa = NULL, **list = NULL;

    list = calloc(2, sizeof(*list));
    if (list == NULL)
        goto fail;
    pa = calloc(1, sizeof(*pa));
    if (pa == NULL)
        goto fail;
    pa->magic = KV5M_PA_DATA;
    pa->pa_type = KRB5_PADATA_SPAKE;
    pa->length = data->length;
    pa->contents = (uint8_t *)data->data;
    list[0] = pa;
    list[1] = NULL;
    *pa_out = list;
    free(data);
    return 0;

fail:
    free(list);
    free(pa);
    free(data->data);
    free(data);
    return ENOMEM;
}

/* Update the transcript checksum tcksum with its current value and data, using
 * ikey for the keyed checksum.  Allocate tcksum if it is empty. */
krb5_error_code
update_tcksum(krb5_context context, krb5_data *tcksum,
              const krb5_keyblock *ikey, const krb5_data *data)
{
    krb5_error_code ret;
    krb5_cksumtype cksumtype;
    size_t cksumlen;
    krb5_crypto_iov iov[3];

    ret = krb5int_c_mandatory_cksumtype(context, ikey->enctype, &cksumtype);
    if (ret)
        return ret;

    if (tcksum->length == 0) {
        /* Initialize the transcript checksum to all zeros. */
        ret = krb5_c_checksum_length(context, cksumtype, &cksumlen);
        if (ret)
            return ret;
        ret = alloc_data(tcksum, cksumlen);
        if (ret)
            return ret;
    }

    /* Compute a keyed checksum over the current value and the input data,
     * writing the result back into tcksum. */
    iov[0].flags = iov[1].flags = KRB5_CRYPTO_TYPE_DATA;
    iov[0].data = *tcksum;
    iov[1].data = *data;
    iov[2].flags = KRB5_CRYPTO_TYPE_CHECKSUM;
    iov[2].data = *tcksum;
    return krb5_c_make_checksum_iov(context, cksumtype, ikey,
                                    KRB5_KEYUSAGE_SPAKE_TRANSCRIPT, iov, 3);
}

/* Like update_tcksum(), but make a copy of an input checksum before
 * updating. */
krb5_error_code
next_tcksum(krb5_context context, const krb5_keyblock *ikey,
            const krb5_data *tcksum_in, const krb5_data *data,
            krb5_data *tcksum_out)
{
    if (krb5int_copy_data_contents(context, tcksum_in, tcksum_out) != 0)
        return ENOMEM;
    return update_tcksum(context, tcksum_out, ikey, data);
}

/*
 * Derive K'[n] from the initial key, the SPAKE result, the transcript
 * checksum, and the encoded KDC-REQ-BODY.  Place the result in allocated
 * storage in *out.
 */
krb5_error_code
derive_key(krb5_context context, const krb5_keyblock *ikey,
           const krb5_data *spakeresult, const krb5_data *tcksum,
           const krb5_data *der_req, uint32_t n, krb5_keyblock **out)
{
    krb5_error_code ret;
    struct k5buf buf;
    krb5_data d;
    uint8_t nbuf[4];

    *out = NULL;

    k5_buf_init_dynamic(&buf);
    k5_buf_add(&buf, "SPAKEKey"); /* XXX may change to SPAKEkey */
    /* XXX may change to include group number; add parameter */
    k5_buf_add_len(&buf, spakeresult->data, spakeresult->length);
    k5_buf_add_len(&buf, tcksum->data, tcksum->length);
    k5_buf_add_len(&buf, der_req->data, der_req->length);
    store_32_be(n, nbuf);
    k5_buf_add_len(&buf, nbuf, 4);
    if (buf.data == NULL)
        return ENOMEM;

    d = make_data(buf.data, buf.len);
    ret = krb5_c_derive_prfplus(context, ikey, &d, ENCTYPE_NULL, out);
    if (!ret)
        TRACE_SPAKE_DERIVE_KEY(context, n, *out);
    k5_buf_free(&buf);
    return ret;
}
