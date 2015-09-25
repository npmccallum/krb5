/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/groups.c - SPAKE group interfaces */
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

/*
 * The SPAKE2 algorithm works as follows:
 *
 * 1. The parties agree on a group, a base element G, and constant elements M
 *    and N.  In this mechanism, these parameters are determined by the
 *    registered group number.
 * 2. Both parties derive a scalar value w from the initial key.
 * 3. The first party (the KDC, in this mechanism) chooses a random secret
 *    scalar x and sends T=xG+wM.
 * 4. The second party (the client, in this mechanism) chooses a random
 *    secret scalar y and sends S=yG+wN.
 * 5. The first party computes K=x(S-wN).
 * 6. the second party computes the same value as K=y(T-wM).
 * 7. Both parties derive a key from a random oracle whose input incorporates
 *    the party identities, w, T, S, and K.
 *
 * We implement the algorithm using a vtable for each group, where the primary
 * vtable methods are "keygen" (corresponding to step 3 or 4) and "result"
 * (corresponding to step 5 or 6).  We use the term "private scalar" to refer
 * to x or y, and "public element" to refer to S or T.
 */

#include "k5-int.h"
#include "internal.h"

#define DEFAULT_GROUPS_CLIENT "p256"
#define DEFAULT_GROUPS_KDC ""

typedef struct groupent_st {
    const groupdef *gdef;
    void *gdata;
} groupent;

struct groupstate_st {
    krb5_boolean is_kdc;

    /* Permitted and groups, from configuration */
    int32_t *permitted;
    size_t npermitted;

    /* Optimistic challenge group, from configuration */
    int32_t challenge_group;

    /* Lazily-initialized list of gdata objects. */
    groupent *data;
    size_t ndata;
};

/*
 * Two group definitions are needed in order to test rejected optimistic KDC
 * challenge.  We can get rid of this dummy group definition once we have two
 * supported groups.
 */

static krb5_error_code
testgroup_keygen(krb5_context context, void *gdata, const uint8_t *wbytes,
                 krb5_boolean use_m, uint8_t *priv_out, uint8_t *pub_out)
{
    *priv_out = 0;
    *pub_out = 0;
    return 0;
}

static krb5_error_code
testgroup_result(krb5_context context, void *gdata, const uint8_t *wbytes,
                 const uint8_t *ourpriv, const uint8_t *theirpub,
                 krb5_boolean use_m, uint8_t *elem_out)
{
    return EINVAL;
}

static const groupdef groupdefs[] = {
#ifdef SPAKE_OPENSSL
    { "p256", GROUP_P256, 32, 33,
      p256_init, ossl_keygen, ossl_result, ossl_free },
#endif
    { "testdonotuse", -1111, 1, 1,
      NULL, testgroup_keygen, testgroup_result, NULL }
};

/* Find a groupdef structure by group number; return NULL on failure. */
static const groupdef *
find_gdef(int32_t group)
{
    size_t i;

    for (i = 0; i < sizeof(groupdefs) / sizeof(*groupdefs); i++) {
        if (groupdefs[i].group == group)
            return &groupdefs[i];
    }
    return NULL;
}

/* Find a group number by name (case-insensitive); return 0 on failure. */
static int32_t
find_gnum(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(groupdefs) / sizeof(*groupdefs); i++) {
        if (strcasecmp(name, groupdefs[i].name) == 0)
            return groupdefs[i].group;
    }
    return 0;
}

static krb5_boolean
in_grouplist(const int32_t *list, size_t count, int32_t group)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (list[i] == group)
            return TRUE;
    }
    return FALSE;
}

/* Retrieve a group data object for group within gstate, lazily initializing it
 * if necessary. */
static krb5_error_code
get_gdata(krb5_context context, groupstate *gstate, const groupdef *gdef,
          void **gdata_out)
{
    krb5_error_code ret;
    groupent *ent, *newptr;

    *gdata_out = NULL;

    /* Look for an existing entry. */
    for (ent = gstate->data; ent < gstate->data + gstate->ndata; ent++) {
        if (ent->gdef == gdef) {
            *gdata_out = ent->gdata;
            return 0;
        }
    }

    /* Make a new entry. */
    newptr = realloc(gstate->data, (gstate->ndata + 1) * sizeof(groupent));
    if (newptr == NULL)
        return ENOMEM;
    gstate->data = newptr;
    ent = &gstate->data[gstate->ndata];
    ent->gdef = gdef;
    ent->gdata = NULL;
    if (gdef->init_gdata != NULL) {
        ret = gdef->init_gdata(context, gdef, &ent->gdata);
        if (ret)
            return ret;
    }
    gstate->ndata++;
    *gdata_out = ent->gdata;
    return 0;
}

/* Destructively parse str into a list of group numbers. */
static krb5_error_code
parse_groups(krb5_context context, char *str, int32_t **list_out,
             size_t *count_out)
{
    const char *const delim = " \t\r\n,";
    char *token, *save = NULL;
    int32_t group, *newptr, *list = NULL;
    size_t count = 0;

    *list_out = NULL;
    *count_out = 0;

    /* Walk through the words in profstr. */
    for (token = strtok_r(str, delim, &save); token != NULL;
         token = strtok_r(NULL, delim, &save)) {
        group = find_gnum(token);
        if (!group) {
            TRACE_SPAKE_UNKNOWN_GROUP(context, token);
            continue;
        }
        if (in_grouplist(list, count, group))
            continue;
        newptr = realloc(list, (count + 1) * sizeof(*list));
        if (newptr == NULL) {
            free(list);
            return ENOMEM;
        }
        list = newptr;
        list[count++] = group;
    }

    *list_out = list;
    *count_out = count;
    return 0;
}

/* Initialize an object which holds group configuration as well as
 * lazily-initialized pre-computation state for each group. */
krb5_error_code
group_init_state(krb5_context context, krb5_boolean is_kdc,
                 groupstate **gstate_out)
{
    krb5_error_code ret;
    groupstate *gstate;
    const char *defgroups;
    char *profstr1 = NULL, *profstr2 = NULL;
    int32_t *permitted = NULL, challenge_group = 0;
    size_t npermitted;

    *gstate_out = NULL;

    defgroups = is_kdc ? DEFAULT_GROUPS_KDC : DEFAULT_GROUPS_CLIENT;
    ret = profile_get_string(context->profile, KRB5_CONF_LIBDEFAULTS,
                             KRB5_CONF_SPAKE_PREAUTH_GROUPS, NULL, defgroups,
                             &profstr1);
    if (ret)
        goto cleanup;
    ret = parse_groups(context, profstr1, &permitted, &npermitted);
    if (ret)
        goto cleanup;
    if (npermitted == 0) {
        ret = KRB5_PLUGIN_OP_NOTSUPP;
        k5_setmsg(context, ret, _("No SPAKE preauth groups configured"));
        goto cleanup;
    }

    if (is_kdc) {
        /*
         * Check for a configured optimistic challenge group.  If one is set,
         * the KDC will send a challenge in the PREAUTH_REQUIRED method data,
         * before receiving the list of supported groups.
         */
        ret = profile_get_string(context->profile, KRB5_CONF_LIBDEFAULTS,
                                 KRB5_CONF_SPAKE_PREAUTH_KDC_CHALLENGE, NULL,
                                 NULL, &profstr2);
        if (ret)
            goto cleanup;
        if (profstr2 != NULL) {
            challenge_group = find_gnum(profstr2);
            if (!in_grouplist(permitted, npermitted, challenge_group))
                TRACE_SPAKE_BAD_KDC_CHALLENGE_GROUP(context, profstr2);
        }
    }

    gstate = k5alloc(sizeof(*gstate), &ret);
    if (gstate == NULL)
        goto cleanup;
    gstate->is_kdc = is_kdc;
    gstate->permitted = permitted;
    gstate->npermitted = npermitted;
    gstate->challenge_group = challenge_group;
    permitted = NULL;
    gstate->data = NULL;
    gstate->ndata = 0;
    *gstate_out = gstate;

cleanup:
    profile_release_string(profstr1);
    profile_release_string(profstr2);
    free(permitted);
    return ret;
}

/* Return true if group is permitted by configuration. */
krb5_boolean
group_is_permitted(groupstate *gstate, int32_t group)
{
    return in_grouplist(gstate->permitted, gstate->npermitted, group);
}

/* Get the list of groups permitted by configuration. */
void
group_get_permitted(groupstate *gstate, int32_t **list_out, int32_t *count_out)
{
    *list_out = gstate->permitted;
    *count_out = gstate->npermitted;
}

/* Get the KDC optimistic challenge group if one is configured.  Valid for KDC
 * grouptstate objects only. */
krb5_int32
group_optimistic_challenge(groupstate *gstate)
{
    assert(gstate->is_kdc);
    return gstate->challenge_group;
}

/* Derive an unsanitized byte vector of length len for the SPAKE w input from
 * ikey.  Place result in allocated storage in *wbytes_out. */
static krb5_error_code
derive_wbytes(krb5_context context, const krb5_keyblock *ikey, size_t len,
              uint8_t **wbytes_out)
{
    krb5_error_code ret;
    uint8_t *wbytes;
    krb5_data d, prf_input = string2data("SPAKEsecret");

    *wbytes_out = NULL;

    wbytes = malloc(len);
    if (wbytes == NULL)
        return ENOMEM;
    /* XXX draft will change to include group number in PRF+ input */
    d = make_data(wbytes, len);
    ret = krb5_c_prfplus(context, ikey, &prf_input, &d);
    if (ret) {
        free(wbytes);
        return ret;
    }
    *wbytes_out = wbytes;
    return 0;
}

/*
 * Generate a SPAKE private scalar (x or y) and public element (T or S),
 * deriving the input scalar w from ikey.  Use constant M if is_kdc is true, N
 * if it is false.  Place the results in allocated storage in *priv_out and
 * *pub_out.
 */
krb5_error_code
group_keygen(krb5_context context, groupstate *gstate, int32_t group,
             const krb5_keyblock *ikey, krb5_data *priv_out,
             krb5_data *pub_out)
{
    krb5_error_code ret;
    const groupdef *gdef;
    void *gdata;
    uint8_t *wbytes = NULL, *priv = NULL, *pub = NULL;

    *priv_out = empty_data();
    *pub_out = empty_data();
    gdef = find_gdef(group);
    if (gdef == NULL)
        return EINVAL;
    ret = get_gdata(context, gstate, gdef, &gdata);
    if (ret)
        return ret;

    ret = derive_wbytes(context, ikey, gdef->scalar_len, &wbytes);
    if (ret)
        goto cleanup;
    priv = k5alloc(gdef->scalar_len, &ret);
    if (priv == NULL)
        goto cleanup;
    pub = k5alloc(gdef->elem_len, &ret);
    if (pub == NULL)
        goto cleanup;

    ret = gdef->keygen(context, gdata, wbytes, gstate->is_kdc, priv, pub);
    if (ret)
        goto cleanup;

    *priv_out = make_data(priv, gdef->scalar_len);
    *pub_out = make_data(pub, gdef->elem_len);
    priv = pub = NULL;
    TRACE_SPAKE_KEYGEN(context, pub_out);

cleanup:
    zapfree(wbytes, gdef->scalar_len);
    zapfree(priv, gdef->scalar_len);
    free(pub);
    return ret;
}

/*
 * Compute the SPAKE result K from our private scalar (x or y) and their public
 * key (S or T), deriving the input scalar w from ikey.  Use the other party's
 * constant, N if is_kdc is true or M if false.
 */
krb5_error_code
group_result(krb5_context context, groupstate *gstate, int32_t group,
             const krb5_keyblock *ikey, const krb5_data *ourpriv,
             const krb5_data *theirpub, krb5_data *spakeresult_out)
{
    krb5_error_code ret;
    const groupdef *gdef;
    void *gdata;
    uint8_t *wbytes = NULL, *spakeresult = NULL;

    *spakeresult_out = empty_data();
    gdef = find_gdef(group);
    if (gdef == NULL)
        return EINVAL;
    if (ourpriv->length != gdef->scalar_len ||
        theirpub->length != gdef->elem_len)
        return EINVAL;
    ret = get_gdata(context, gstate, gdef, &gdata);
    if (ret)
        return ret;

    ret = derive_wbytes(context, ikey, gdef->scalar_len, &wbytes);
    if (ret)
        goto cleanup;
    spakeresult = k5alloc(gdef->elem_len, &ret);
    if (spakeresult == NULL)
        goto cleanup;

    /* Invert is_kdc here to use the other party's constant. */
    ret = gdef->result(context, gdata, wbytes, (uint8_t *)ourpriv->data,
                       (uint8_t *)theirpub->data, !gstate->is_kdc,
                       spakeresult);
    if (ret)
        goto cleanup;

    *spakeresult_out = make_data(spakeresult, gdef->elem_len);
    spakeresult = NULL;
    TRACE_SPAKE_RESULT(context, spakeresult_out);

cleanup:
    zapfree(wbytes, gdef->scalar_len);
    zapfree(spakeresult, gdef->elem_len);
    return ret;
}

void
group_free_state(groupstate *gstate)
{
    groupent *ent;

    for (ent = gstate->data; ent < gstate->data + gstate->ndata; ent++) {
        if (ent->gdata != NULL && ent->gdef->free_gdata != NULL)
            ent->gdef->free_gdata(ent->gdata);
    }
    free(gstate->data);
}
