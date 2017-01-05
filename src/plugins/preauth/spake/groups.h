/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/groups.h - SPAKE group interfaces */
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

#ifndef GROUPS_H
#define GROUPS_H

#include "k5-int.h"

typedef struct groupstate_st groupstate;
typedef struct groupdata_st groupdata;
typedef struct groupdef_st groupdef;

struct groupdef_st {
    int32_t id;

    /*
     * Optional: create a per-group data object to allow more efficient keygen
     * and result computations.  Saving a reference to gdef is okay; its
     * lifetime will always be longer than the resulting object.
     */
    krb5_error_code (*init)(krb5_context context, const groupdef *gdef,
                            groupdata **gdata_out);

    /*
     * Mandatory: generate a random private scalar (x or y) and a public
     * element (T or S), using wbytes for the w value.  If use_m is true, use
     * the M element (generating T); otherwise use the N element (generating
     * S).  wbytes and prv_out have length scal_len; pub_out has length
     * elem_lem.
     */
    krb5_error_code (*keygen)(krb5_context context, groupdata *gdata,
                              const uint8_t *wbytes, krb5_boolean use_m,
                              uint8_t *prv_out, uint8_t *pub_out);

    /*
     * Mandatory: compute K given a private scalar (x or y) and the other
     * party's public element (S or T), using wbytes for the w value.  If use_m
     * is true, use the M element (computing K from y and T); otherwise use the
     * N element (computing K from x and S).  wbytes and ourpriv have length
     * scal_len; theirpub and K_out have length elem_len.
     */
    krb5_error_code (*result)(krb5_context context, groupdata *gdata,
                              const uint8_t *wbytes, const uint8_t *ourprv,
                              const uint8_t *theirpub, krb5_boolean use_m,
                              uint8_t *elem_out);

    /* Optional: release a group data object. */
    void (*fini)(groupdata *gdata);
};

krb5_error_code group_init_state(krb5_context context, krb5_boolean is_kdc,
                                 groupstate **out);

krb5_boolean group_is_permitted(groupstate *gstate, int32_t group);

void group_get_permitted(groupstate *gstate, int32_t **list_out,
                         int32_t *count_out);

krb5_int32 group_optimistic_challenge(groupstate *group);

krb5_error_code group_keygen(krb5_context context, groupstate *gstate,
                             int32_t group, const krb5_keyblock *ikey,
                             krb5_data *prv_out, krb5_data *pub_out);

krb5_error_code group_result(krb5_context context, groupstate *gstate,
                             int32_t group, const krb5_keyblock *ikey,
                             const krb5_data *ourprv,
                             const krb5_data *theirpub,
                             krb5_data *spakeresult_out);

void group_free_state(groupstate *gstate);

#endif /* GROUPS_H */
