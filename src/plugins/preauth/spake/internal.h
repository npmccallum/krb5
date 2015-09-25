/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/internal.h - SPAKE internal function declarations */
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

#ifndef INTERNAL_H
#define INTERNAL_H

#include "k5-int.h"

/* Group configuration and group-specific SPAKE algorithm operations */
typedef struct groupstate_st groupstate;
krb5_error_code group_init_state(krb5_context context, krb5_boolean is_kdc,
                                 groupstate **out);
krb5_boolean group_is_permitted(groupstate *gstate, int32_t group);
void group_get_permitted(groupstate *gstate, int32_t **list_out,
                         int32_t *count_out);
krb5_int32 group_optimistic_challenge(groupstate *group);
krb5_error_code group_keygen(krb5_context context, groupstate *gstate,
                             int32_t group, const krb5_keyblock *ikey,
                             krb5_data *priv_out, krb5_data *pub_out);
krb5_error_code group_result(krb5_context context, groupstate *gstate,
                             int32_t group, const krb5_keyblock *ikey,
                             const krb5_data *ourpriv,
                             const krb5_data *theirpub,
                             krb5_data *spakeresult_out);
void group_free_state(groupstate *gstate);


/* Utility functions not specific to groups */
krb5_error_code convert_to_padata(krb5_data *data, krb5_pa_data ***pa_out);
krb5_error_code update_tcksum(krb5_context context, krb5_data *tcksum,
                              const krb5_keyblock *ikey,
                              const krb5_data *data);
krb5_error_code next_tcksum(krb5_context context, const krb5_keyblock *ikey,
                            const krb5_data *tcksum_in, const krb5_data *data,
                            krb5_data *tcksum_out);
krb5_error_code derive_key(krb5_context context, const krb5_keyblock *ikey,
                           const krb5_data *spakeresult,
                           const krb5_data *tcksum, const krb5_data *derreq,
                           uint32_t n, krb5_keyblock **out);

/* Second-factor constants */
#define SF_NONE 1

/* Group implementation details */

/* XXX dummy assignment */
#define GROUP_P256 1 /* SEC 2 secp256r1 with compressed points */

typedef struct groupdef_st groupdef;
struct groupdef_st {
    /* The group name and number. */
    const char *name;
    int32_t group;

    /*
     * Byte length of a marshalled scalar.  For now, we assume that this value
     * is also the number of pseudo-random input bytes needed to generate the
     * scalar w input to the SPAKE algorithm.
     */
    size_t scalar_len;

    /* Byte length of a marshalled group element. */
    size_t elem_len;

    /*
     * Optional: create a per-group data object to allow more efficient keygen
     * and result computations.  Saving a copy of gdef is okay; its lifetime
     * will always be longer than the resulting object.
     */
    krb5_error_code (*init_gdata)(krb5_context context, const groupdef *gdef,
                                  void **gdata_out);

    /*
     * Mandatory: generate a random private scalar (x or y) and a public
     * element (T or S), using wbytes for the w value.  If use_m is true, use
     * the M element (generating T); otherwise use the N element (generating
     * S).  wbytes and priv_out have length scalar_len; pub_out has length
     * elem_lem.
     */
    krb5_error_code (*keygen)(krb5_context context, void *gdata,
                              const uint8_t *wbytes, krb5_boolean use_m,
                              uint8_t *priv_out, uint8_t *pub_out);

    /*
     * Mandatory: compute K given a private scalar (x or y) and the other
     * party's public element (S or T), using wbytes for the w value.  If use_m
     * is true, use the M element (computing K from y and T); otherwise use the
     * N element (computing K from x and S).  wbytes and ourpriv have length
     * scalar_len; theirpub and K_out have length elem_len.
     */
    krb5_error_code (*result)(krb5_context context, void *gdata,
                              const uint8_t *wbytes, const uint8_t *ourpriv,
                              const uint8_t *theirpub, krb5_boolean use_m,
                              uint8_t *elem_out);

    /* Optional: release a group data object. */
    void (*free_gdata)(void *gdata);
};

/* Group constants, expressed in marshalled point form */
#define P256_M (uint8_t *)                                              \
    "\x02\x88\x6E\x2F\x97\xAC\xE4\x6E\x55\xBA\x9D\xD7\x24\x25\x79\xF2"  \
    "\x99\x3B\x64\xE1\x6E\xF3\xDC\xAB\x95\xAF\xD4\x97\x33\x3D\x8F\xA1\x2F"
#define P256_N (uint8_t *)                                             \
    "\x03\xD8\xBB\xD6\xC6\x39\xC6\x29\x37\xB0\x4D\x99\x7F\x38\xC3\x77" \
    "\x07\x19\xC6\x29\xD7\x01\x4D\x49\xA2\x4B\x4F\x98\xBA\xA1\x29\x2B\x49"

/* Implementation of GROUP_P256 from openssl.c */
krb5_error_code p256_init(krb5_context context, const groupdef *gdef,
                          void **gdata_out);
krb5_error_code ossl_keygen(krb5_context context, void *gdata,
                            const uint8_t *wbytes, krb5_boolean use_m,
                            uint8_t *priv_out, uint8_t *pub_out);
krb5_error_code ossl_result(krb5_context context, void *gdata,
                            const uint8_t *wbytes, const uint8_t *ourpriv,
                            const uint8_t *theirpub, krb5_boolean use_m,
                            uint8_t *elem_out);
void ossl_free(void *gdata);

/* Tracing macros */
/* XXX display groups by name? */
/* XXX display group list for support messages? */

#define TRACE_SPAKE_BAD_KDC_CHALLENGE_GROUP(c, name)                    \
    TRACE(c, "SPAKE KDC challenge group not a permitted group: {string}", name)
#define TRACE_SPAKE_DERIVE_KEY(c, n, kb)                        \
    TRACE(c, "SPAKE derived K'[{int}] = {keyblock}", n, kb)
#define TRACE_SPAKE_KEYGEN(c, pubkey)                                   \
    TRACE(c, "SPAKE key generated with pubkey {hexdata}", pubkey)
#define TRACE_SPAKE_RECEIVE_CHALLENGE(c, group, pubkey)                 \
    TRACE(c, "SPAKE challenge received with group {int}, pubkey {hexdata}", \
          group, pubkey)
#define TRACE_SPAKE_RECEIVE_RESPONSE(c, pubkey)                         \
    TRACE(c, "SPAKE response received with pubkey {hexdata}", pubkey)
#define TRACE_SPAKE_RECEIVE_SUPPORT(c, group)                           \
    TRACE(c, "SPAKE support message received, selected group {int}", group)
#define TRACE_SPAKE_REJECT_CHALLENGE(c, group)                          \
    TRACE(c, "SPAKE challenge with group {int} rejected", (int)group)
#define TRACE_SPAKE_REJECT_SUPPORT(c)           \
    TRACE(c, "SPAKE support message rejected")
#define TRACE_SPAKE_RESULT(c, result)                           \
    TRACE(c, "SPAKE algorithm result: {hexdata}", result)
#define TRACE_SPAKE_SEND_CHALLENGE(c, group)                    \
    TRACE(c, "Sending SPAKE challenge with group {int}", group)
#define TRACE_SPAKE_SEND_RESPONSE(c)            \
    TRACE(c, "Sending SPAKE response")
#define TRACE_SPAKE_SEND_SUPPORT(c)             \
    TRACE(c, "Sending SPAKE support message")
#define TRACE_SPAKE_TCKSUM(c, tcksum)                                   \
    TRACE(c, "SPAKE final transcript checksum: {hexdata}", tcksum)
#define TRACE_SPAKE_UNKNOWN_GROUP(c, name)                      \
    TRACE(c, "Unrecognized SPAKE group name: {string}", name)

#endif /* INTERNAL_H */
