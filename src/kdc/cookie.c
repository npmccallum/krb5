/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kdc/cookie.c - Secure Cookies */
/*
 * Copyright 2015 Red Hat, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <k5-int.h>
#include "cookie.h"

/* Number from internal use reserved; see RFC 4120 7.5.1. */
#define KEYUSAGE_PA_FX_COOKIE 513

/* Let cookies be valid for one hour. */
#define COOKIE_LIFETIME 3600

static krb5_error_code
princ2data(krb5_const_principal princ, krb5_data *out)
{
    krb5_error_code retval;
    size_t size = 0;

    for (int i = 0; i < princ->length; i++)
        size += princ->data[i].length;
    size += princ->realm.length;
    size += princ->length;

    retval = alloc_data(out, size);
    if (retval != 0)
        return retval;

    size = 0;
    for (int i = 0; i < princ->length; i++) {
        if (i != 0)
            memcpy(out->data + size++, "/", 1);

        memcpy(out->data + size, princ->data[i].data, princ->data[i].length);
        size += princ->data[i].length;
    }

    memcpy(out->data + size++, "@", 1);
    memcpy(out->data + size, princ->realm.data, princ->realm.length);
    return 0;
}

static krb5_error_code
load_key(krb5_context context, krb5_const_principal cprinc,
         krb5_db_entry *tgs_entry, krb5_enctype etype, krb5_keyblock **key)
{
    krb5_key_data *kdata = NULL;
    krb5_error_code retval = 0;
    krb5_keyblock kblock = {};
    krb5_data input = {};
    krb5_int32 start = 0;

    /* Find the key with the specified enctype. */
    retval = krb5_dbe_search_enctype(context, tgs_entry, &start,
                                     etype, -1, 0, &kdata);
    if (retval != 0)
        return retval;

    /* Decrypt the key. */
    retval = krb5_dbe_decrypt_key_data(context, NULL, kdata, &kblock, NULL);
    if (retval != 0)
        return retval;

    /* Convert the client principal to krb5_data. */
    retval = princ2data(cprinc, &input);
    if (retval != 0) {
        krb5_free_keyblock_contents(context, &kblock);
        return errno;
    }

    /* Run the PRF over the key and client principal. */
    retval = krb5_c_derive(context, &kblock, &input, key);
    krb5_free_keyblock_contents(context, &kblock);
    krb5_free_data_contents(context, &input);
    return retval;
}

static krb5_error_code
cdecrypt(krb5_context context, const krb5_keyblock *key,
         const krb5_enc_data *ed, krb5_pa_data ***cookie)
{
    krb5_secure_cookie *c = NULL;
    krb5_error_code retval = 0;
    krb5_timestamp now = 0;
    krb5_data pt = {};

    /* Get the time. */
    retval = krb5_timeofday(context, &now);
    if (retval != 0)
        return retval;

    /* Prepare input for decryption. */
    pt.length = ed->ciphertext.length;
    pt.data = malloc(pt.length);
    if (pt.data == NULL)
        return ENOMEM;

    /* Perform decryption. */
    retval = krb5_c_decrypt(context, key, KEYUSAGE_PA_FX_COOKIE,
                            NULL, ed, &pt);
    if (retval != 0) {
        krb5_free_data_contents(context, &pt);
        return retval;
    }

    /* Decode the cookie. */
    retval = decode_krb5_secure_cookie(&pt, &c);
    krb5_free_data_contents(context, &pt);
    if (retval != 0)
        return retval;

    /* Determine if the cookie is expired. */
    if (c->time + COOKIE_LIFETIME < now) {
        k5_free_secure_cookie(context, c);
        return KRB5KDC_ERR_PREAUTH_EXPIRED;
    }

    /* Steal the data array. */
    *cookie = c->data;
    c->data = NULL;
    k5_free_secure_cookie(context, c);
    return 0;
}

static krb5_error_code
cencrypt(krb5_context context, const krb5_keyblock *key,
         krb5_pa_data * const*cookie, krb5_pa_data **padata)
{
    krb5_secure_cookie c = { 0, (krb5_pa_data **)cookie };
    krb5_error_code retval = 0;
    krb5_enc_data ct = {};
    krb5_data *pt = NULL;
    krb5_data *ed = NULL;
    size_t ctlen;

    /* Get the time. */
    retval = krb5_timeofday(context, &c.time);
    if (retval != 0)
        return retval;

    /* Encode the cookie. */
    retval = encode_krb5_secure_cookie(&c, &pt);
    if (retval != 0)
        return retval;

    /* Find out how much buffer to allocate. */
    retval = krb5_c_encrypt_length(context, key->enctype,
                                   pt->length, &ctlen);
    if (retval != 0) {
        krb5_free_data(context, pt);
        return retval;
    }

    /* Allocate the output buffer. */
    ct.ciphertext.length = ctlen;
    ct.ciphertext.data = malloc(ctlen);
    if (ct.ciphertext.data == NULL) {
        krb5_free_data(context, pt);
        retval = ENOMEM;
        return retval;
    }

    /* Perform the encryption. */
    retval = krb5_c_encrypt(context, key, KEYUSAGE_PA_FX_COOKIE,
                            NULL, pt, &ct);
    krb5_free_data(context, pt);
    if (retval != 0) {
        free(ct.ciphertext.data);
        return retval;
    }

    /* Encode to EncryptedData. */
    retval = encode_krb5_enc_data(&ct, &ed);
    free(ct.ciphertext.data);
    if (retval != 0)
        return retval;

    /* Steal the encrypted data buffer for the cookie. */
    *padata = calloc(1, sizeof(krb5_pa_data));
    if (*padata == NULL) {
        retval = ENOMEM;
    } else {
        (*padata)->pa_type = KRB5_PADATA_FX_COOKIE;
        (*padata)->length = ed->length;
        (*padata)->contents = (krb5_octet *)ed->data;
        ed->data = NULL;
    }

    krb5_free_data(context, ed);
    return retval;
}

krb5_error_code
cookie_decrypt(krb5_context context, krb5_const_principal cprinc,
               krb5_db_entry *tgs_entry, krb5_pa_data **padata,
               krb5_pa_data ***cookie)
{
    krb5_error_code retval = 0;
    krb5_keyblock *key = NULL;
    krb5_enc_data *ed = NULL;
    size_t i;

    for (i = 0; padata[i] != NULL; i++) {
        krb5_data pt = {
            .data = (char *)padata[i]->contents,
            .length = padata[i]->length
        };

        if (padata[i]->pa_type != KRB5_PADATA_FX_COOKIE)
            continue;

        /* Parse the incoming data. */
        krb5_free_enc_data(context, ed);
        ed = NULL;
        retval = decode_krb5_enc_data(&pt, &ed);
        if (retval != 0)
            break;

        /* Find a key. */
        retval = load_key(context, cprinc, tgs_entry, ed->enctype, &key);
        if (retval != 0)
            break;

        /* Decrypt the cookie. */
        retval = cdecrypt(context, key, ed, cookie);
        krb5_free_keyblock(context, key);
        break;
    }

    krb5_free_enc_data(context, ed);
    return retval;
}

krb5_error_code
cookie_encrypt(krb5_context context, krb5_const_principal cprinc,
               krb5_db_entry *tgs_entry, krb5_pa_data * const *cookie,
               krb5_pa_data ***padata)
{
    krb5_pa_data **tmp = *padata;
    krb5_error_code retval = 0;
    krb5_keyblock *key = NULL;
    size_t i;

    if (cookie == NULL)
        return 0;

    for (i = 0; tmp != NULL && tmp[i] != NULL; i++) {
        if (tmp[i]->pa_type == KRB5_PADATA_FX_COOKIE)
            return EALREADY;
    }

    tmp = realloc(tmp, sizeof(krb5_pa_data *) * (i + 2));
    if (tmp == NULL)
        return ENOMEM;
    tmp[i + 1] = NULL;
    *padata = tmp;

    retval = load_key(context, cprinc, tgs_entry, -1, &key);
    if (retval != 0)
        return retval;

    retval = cencrypt(context, key, cookie, &tmp[i]);
    krb5_free_keyblock(context, key);
    return retval;
}
