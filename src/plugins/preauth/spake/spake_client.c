/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/spake_client.c - SPAKE clpreauth module */
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
#include "k5-spake.h"
#include "internal.h"
#include <krb5/clpreauth_plugin.h>

typedef struct reqstate_st {
    krb5_keyblock *initial_key;
    krb5_data *support;
    krb5_data tcksum;
    krb5_data spakeresult;
} reqstate;

static krb5_error_code
spake_init(krb5_context context, krb5_clpreauth_moddata *moddata_out)
{
    krb5_error_code ret;
    groupstate *gstate;

    ret = group_init_state(context, FALSE, &gstate);
    if (ret)
        return ret;
    *moddata_out = (krb5_clpreauth_moddata)gstate;
    return 0;
}

static void
spake_fini(krb5_context context, krb5_clpreauth_moddata moddata)
{
    group_free_state((groupstate *)moddata);
}

static void
spake_request_init(krb5_context context, krb5_clpreauth_moddata moddata,
                   krb5_clpreauth_modreq *modreq_out)
{
    *modreq_out = calloc(1, sizeof(reqstate));
}

static void
spake_request_fini(krb5_context context, krb5_clpreauth_moddata moddata,
                   krb5_clpreauth_modreq modreq)
{
    reqstate *st = (reqstate *)modreq;

    krb5_free_keyblock(context, st->initial_key);
    krb5_free_data(context, st->support);
    krb5_free_data_contents(context, &st->tcksum);
    zapfree(st->spakeresult.data, st->spakeresult.length);
    free(st);
}

static krb5_error_code
spake_prep_questions(krb5_context context, krb5_clpreauth_moddata moddata,
                     krb5_clpreauth_modreq modreq,
                     krb5_get_init_creds_opt *opt, krb5_clpreauth_callbacks cb,
                     krb5_clpreauth_rock rock, krb5_kdc_req *req,
                     krb5_data *enc_req, krb5_data *enc_prev_req,
                     krb5_pa_data *pa_data)
{
    reqstate *st = (reqstate *)modreq;

    if (st == NULL)
        return ENOMEM;
    if (st->initial_key == NULL && pa_data->length > 0)
        cb->need_as_key(context, rock);
    /* XXX ask for more based on factor challenges, or return an error
     * if no factors supported */
    return 0;
}

/*
 * Output a PA-SPAKE support message indicating which groups we support.  This
 * may be done for optimistic preauth, in response to an empty message, or in
 * response to a challenge using a group we do not support.  Save the support
 * message in st->support.
 */
static krb5_error_code
send_support(krb5_context context, groupstate *gstate, reqstate *st,
             krb5_pa_data ***pa_out)
{
    krb5_error_code ret;
    krb5_data *support;
    krb5_pa_spake msg;

    msg.choice = SPAKE_MSGTYPE_SUPPORT;
    group_get_permitted(gstate, &msg.u.support.groups, &msg.u.support.ngroups);
    ret = encode_krb5_pa_spake(&msg, &support);
    if (ret)
        return ret;

    /* Save the message for the transcript checksum later; we may not know the
     * correct initial reply key if we're doing optimistic preauth. */
    ret = krb5_copy_data(context, support, &st->support);
    if (ret) {
        krb5_free_data(context, support);
        return ret;
    }

    TRACE_SPAKE_SEND_SUPPORT(context);
    return convert_to_padata(support, pa_out);
}

static krb5_error_code
process_challenge(krb5_context context, groupstate *gstate, reqstate *st,
                  krb5_spake_challenge *ch, const krb5_data *der_msg,
                  krb5_clpreauth_callbacks cb, krb5_clpreauth_rock rock,
                  krb5_prompter_fct prompter, void *prompter_data,
                  const krb5_data *der_req, krb5_pa_data ***pa_out)
{
    krb5_error_code ret;
    krb5_keyblock *k0 = NULL, *k1 = NULL;
    krb5_spake_factor factor;
    krb5_pa_spake msg;
    krb5_data *der_factor = NULL, *response;
    krb5_data clpriv = empty_data(), clpub = empty_data();
    krb5_enc_data enc_factor;

    enc_factor.ciphertext = empty_data();

    /* Not expected if we already computed the SPAKE result. */
    if (st->spakeresult.length != 0)
        return KRB5KDC_ERR_PREAUTH_FAILED;

    if (st->support != NULL) {
        /*
         * Update the transcript with the support message we previously sent.
         * This step is deferred until now in case we sent the support message
         * optimistically, before we received the ETYPE-INFO2 information
         * needed to determine the initial reply key.
         */
        ret = update_tcksum(context, &st->tcksum, st->initial_key,
                            st->support);
        if (ret)
            return ret;
    }

    /* Update the transcript with the received challenge. */
    ret = update_tcksum(context, &st->tcksum, st->initial_key, der_msg);
    if (ret)
        return ret;

    if (!group_is_permitted(gstate, ch->group)) {
        /* No point in sending a second support message. */
        TRACE_SPAKE_REJECT_CHALLENGE(context, ch->group);
        if (st->support != NULL)
            return KRB5KDC_ERR_PREAUTH_FAILED;
        return send_support(context, gstate, st, pa_out);
    }

    TRACE_SPAKE_RECEIVE_CHALLENGE(context, ch->group, &ch->pubkey);

    /* XXX check for presence of SF-NONE now, actual factor support later */

    ret = group_keygen(context, gstate, ch->group, st->initial_key, &clpriv,
                       &clpub);
    if (ret)
        goto cleanup;
    ret = group_result(context, gstate, ch->group, st->initial_key, &clpriv,
                       &ch->pubkey, &st->spakeresult);
    if (ret)
        goto cleanup;

    ret = update_tcksum(context, &st->tcksum, st->initial_key, &clpub);
    if (ret)
        goto cleanup;
    TRACE_SPAKE_TCKSUM(context, &st->tcksum);

    /* Replace the reply key with K'[0]. */
    ret = derive_key(context, st->initial_key, &st->spakeresult, &st->tcksum,
                     der_req, 0, &k0);
    if (ret)
        goto cleanup;
    ret = cb->set_as_key(context, rock, k0);
    if (ret)
        goto cleanup;

    /* Encrypt a SPAKESecondFactor message with K'[1]. */
    /* XXX hardcoded SF-NONE for now */
    ret = derive_key(context, st->initial_key, &st->spakeresult, &st->tcksum,
                     der_req, 1, &k1);
    if (ret)
        goto cleanup;
    factor.type = SF_NONE;
    factor.data = NULL;
    ret = encode_krb5_spake_factor(&factor, &der_factor);
    if (ret)
        goto cleanup;
    ret = krb5_encrypt_helper(context, k1, KRB5_KEYUSAGE_SPAKE_FACTOR,
                              der_factor, &enc_factor);
    if (ret)
        goto cleanup;

    /* Encode and output a response message. */
    msg.choice = SPAKE_MSGTYPE_RESPONSE;
    msg.u.response.pubkey = clpub;
    msg.u.response.factor = enc_factor;
    ret = encode_krb5_pa_spake(&msg, &response);
    if (ret)
        goto cleanup;
    TRACE_SPAKE_SEND_RESPONSE(context);
    ret = convert_to_padata(response, pa_out);

cleanup:
    krb5_free_keyblock(context, k0);
    krb5_free_keyblock(context, k1);
    krb5_free_data_contents(context, &enc_factor.ciphertext);
    krb5_free_data_contents(context, &clpub);
    zapfree(clpriv.data, clpriv.length);
    return ret;
}

static krb5_error_code
process_encdata(krb5_context context, reqstate *st, krb5_enc_data *enc,
                krb5_clpreauth_callbacks cb, krb5_clpreauth_rock rock,
                krb5_prompter_fct prompter, void *prompter_data,
                const krb5_data *der_req, krb5_pa_data ***pa_out)
{
    /* Not expected if we haven't sent a response yet. */
    if (st->spakeresult.length == 0)
        return KRB5KDC_ERR_PREAUTH_FAILED;
    /* XXX later */
    /* XXX make sure to derive K'[0] and replace reply key again, in case
     * request has changed */
    /* XXX use der_prev_req (add param) to derive K'[n] to decrypt factor from
     * KDC, der_req to derive K'[n+1] for next message */
    return KRB5_PLUGIN_OP_NOTSUPP;
}

static krb5_error_code
spake_process(krb5_context context, krb5_clpreauth_moddata moddata,
              krb5_clpreauth_modreq modreq, krb5_get_init_creds_opt *opt,
              krb5_clpreauth_callbacks cb, krb5_clpreauth_rock rock,
              krb5_kdc_req *req, krb5_data *der_req, krb5_data *der_prev_req,
              krb5_pa_data *pa_in, krb5_prompter_fct prompter,
              void *prompter_data, krb5_pa_data ***pa_out)
{
    krb5_error_code ret;
    groupstate *gstate = (groupstate *)moddata;
    reqstate *st = (reqstate *)modreq;
    krb5_pa_spake *msg;
    krb5_data in_data;
    krb5_keyblock *as_key;

    if (st == NULL)
        return ENOMEM;

    if (pa_in->length == 0) {
        /* Not expected if we already sent a support message. */
        if (st->support != NULL)
            return KRB5KDC_ERR_PREAUTH_FAILED;
        return send_support(context, gstate, st, pa_out);
    }

    /* We need the initial reply key to process any non-trivial message. */
    if (st->initial_key == NULL) {
        ret = cb->get_as_key(context, rock, &as_key);
        if (ret)
            return ret;
        ret = krb5_copy_keyblock(context, as_key, &st->initial_key);
        if (ret)
            return ret;
    }

    in_data = make_data(pa_in->contents, pa_in->length);
    ret = decode_krb5_pa_spake(&in_data, &msg);
    if (ret)
        return ret;

    if (msg->choice == SPAKE_MSGTYPE_CHALLENGE) {
        ret = process_challenge(context, gstate, st, &msg->u.challenge,
                                &in_data, cb, rock, prompter, prompter_data,
                                der_req, pa_out);
    } else if (msg->choice == SPAKE_MSGTYPE_ENCDATA) {
        ret = process_encdata(context, st, &msg->u.encdata, cb, rock, prompter,
                              prompter_data, der_req, pa_out);
    } else {
        /* Unexpected message type */
        ret = KRB5KDC_ERR_PREAUTH_FAILED;
    }

    k5_free_pa_spake(context, msg);
    return ret;
}

krb5_error_code
clpreauth_spake_initvt(krb5_context context, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable);

krb5_error_code
clpreauth_spake_initvt(krb5_context context, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable)
{
    krb5_clpreauth_vtable vt;
    static krb5_preauthtype pa_types[] = { KRB5_PADATA_SPAKE, 0 };

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_clpreauth_vtable)vtable;
    vt->name = "spake";
    vt->pa_type_list = pa_types;
    vt->init = spake_init;
    vt->fini = spake_fini;
    vt->request_init = spake_request_init;
    vt->request_fini = spake_request_fini;
    vt->process = spake_process;
    vt->prep_questions = spake_prep_questions;
    return 0;
}
