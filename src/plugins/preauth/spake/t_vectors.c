/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/spake/t_vectors.c - SPAKE test vector verification */
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
#include <ctype.h>

struct test {
    krb5_enctype enctype;
    int32_t group;
    const char *ikey;
    const char *x;
    const char *y;
    const char *T;
    const char *S;
    const char *K;
    const char *ochal;
    const char *support;
    const char *challenge;
    const char *tcksum;
    const char *body;
    const char *K0;
    const char *K1;
    const char *K2;
    const char *K3;
} tests[] = {
    { ENCTYPE_DES3_CBC_SHA1, GROUP_P256,
      /* initial key, x, y, T, S, K */
      "850BB51358548CD05E86768C313E3BFEF7511937DCF72C3E",
      "7A024204F7C1BD874DA5E709D4713D60C8A70639EB1167B367A9C3787C65C1E5",
      "6F25E2A25A92118719C78DF48F4FF31E78DE58575487CE1EAF19922AD9B8A714",
      "03ABA16407D732D0B752643BD8C7E7C4DDE5F449A8CD8965EB26615EEF9B646ED9",
      "0285D3EC768F24FBEC6B74D3EB1BD44A8DD40B5EC4161FECAD5896C2342E558F62",
      "03DA7EC21E5120243C19E715232D30E1E2B131D206E023091F4147715C88536DF2",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      "A0093007A0053003020101",
      "A1373035A003020101A123042103ABA16407D732D0B752643BD8C7E7C4DDE5F449A8CD"
      "8965EB26615EEF9B646ED9A20930073005A003020101",
      "8BD14871F66AC83A0F80F30ED9F1626AEA7B26F7",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020110",
      /* K'[0], K'[1], K'[2], K'[3] */
      "E970F7BF5DE9C1E915926ED5D98589AE5116DA946D3E9D38",
      "F826D9A7108389376D2C0475C23B7C8A6B801F46A74FBF29",
      "7CA875FB34F1DFE59D577383C2DAE0FD7F61D023F18A6BF8",
      "E91AD56EEFBA29FE7FF47F9D31541351AB13B34AD034756E"
    },

    { ENCTYPE_ARCFOUR_HMAC, GROUP_P256,
      /* initial key, x, y, T, S, K */
      "8846F7EAEE8FB117AD06BDD830B7586C",
      "03983CA8EA7E9D498C778EA6EB2083E6CE164DBA0FF18E0242AF9FC385776E9A",
      "A0116BE5AB0C1681C8F8E3D0D3290A4CB5D32B1666194CB1D71037D1B83E90EC",
      "022FDD4FDE6B7783C2C5D710F5B21E5ADDCCFD071F24570D9582BE09C5CCC66BBB",
      "03B2BC621C58216F2CEE3C4B621928559A6D9970AC6C4D1D0BC81A914726DFF4C7",
      "030008D1317C319B987123256A5293596549241C6CFFBFF5CD79BE5A4A13FED9CB",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      "A0093007A0053003020101",
      "A1373035A003020101A1230421022FDD4FDE6B7783C2C5D710F5B21E5ADDCCFD071F24"
      "570D9582BE09C5CCC66BBBA20930073005A003020101",
      "82C409CFAF96421361ADA5640A83FE0D",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020117",
      /* K'[0], K'[1], K'[2], K'[3] */
      "D12B85FD92022A73B01A3EE662D3D212",
      "638AFB9099E3463DC043939B0057A469",
      "CF127C10A852AE15E4AA49224E16943B",
      "E348B38E638BA2FE5EDA13BB372F5FCE"
    },

    { ENCTYPE_AES128_CTS_HMAC_SHA1_96, GROUP_P256,
      /* initial key, x, y, T, S, K */
      "FCA822951813FB252154C883F5EE1CF4",
      "CC45782198A6416D1775336D71EACD0549A3E80E966E12778C1745A79A6A5F92",
      "2FCD81B5D24BACE4307BF3262F1205544A5308CC3DFABC08935DDD725129FB7C",
      "03F08F6136C5D4215D7D67CF22869F945A044CD2C7062FA65C9E784EEF3F9F6B67",
      "0379E5428557C36F88316A2F0B1CCE60C86F5FE864962C9DBA7CDA307E79E52DAA",
      "02041A9B3FEFF3CDCD8C7E3BB9C486574FC43A7DB7CC5B89B7D39AA062D7A96BC9",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      "A0093007A0053003020101",
      "A1373035A003020101A123042103F08F6136C5D4215D7D67CF22869F945A044CD2C706"
      "2FA65C9E784EEF3F9F6B67A20930073005A003020101",
      "8CBE2A9D85A7B2176663C474",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020111",
      /* K'[0], K'[1], K'[2], K'[3] */
      "4912F9D43F5D638B75973B42ACFC3951",
      "B25C05E4692C22C53D4140682362A9BE",
      "E0D216E3C5BAEC2144783636E24B8432",
      "94C3C5F910E2E800FD0BAF72849C7124"
    },
    { ENCTYPE_AES256_CTS_HMAC_SHA1_96, GROUP_P256,
      /* initial key, x, y, T, S, K */
      "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1",
      "864A7A50B48D73F1D67E55FD642BFA42AEF9C00B8A64C1B9D450FE4AEC4F217B",
      "9CDF5A865306F3F5151665705B7C709ACB175A5AFB82860DEABCA8D0B341FACD",
      "025DAC91D70371924B62E41F24F9F2D8DC41B4AA6BDAADBE8C3046B98501336493",
      "0320A37A47F13419B245CDB9A567973122779A59F3944B16827DEA1DF5ECC4C9DE",
      "02D623EB8BF59166555E6818BA95A51FF298019DFD600329CE269B85FBB248B439",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      "A0093007A0053003020101",
      "A1373035A003020101A1230421025DAC91D70371924B62E41F24F9F2D8DC41B4AA6BDA"
      "ADBE8C3046B98501336493A20930073005A003020101",
      "7A644D847DA42C0B0292BE3A",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020112",
      /* K'[0], K'[1], K'[2], K'[3] */
      "510A519FA3020CE3F639D44735821A6EBAFCA064811D77CBF6832429488768EC",
      "F46336413ECDE61EB385122E099D7DFED9510E0FDA79AF91DAF987E565C098B3",
      "29C4083601B02DBAD22F91561CD37E42A620B401C856E746790DFEC61BB0D2FA",
      "8DA9A3DA0E344119172F7574E2D2156FFE44A96C6C300C6F267B6BF3D971E28B"
    },

    /* Successful optimistic challenge (no support message in transcript) */
    { ENCTYPE_AES128_CTS_HMAC_SHA1_96, GROUP_P256,
      /* initial key, x, y, T, S, K */
      "FCA822951813FB252154C883F5EE1CF4",
      "1FB797FAB7D6467B2F5A522AF87F43FDF606254131D0B6640589F8779B025244",
      "8B53031D05D51433ADE9B2B4EFDD35F80FA34266CCFDBA9BBA26D85135E8579A",
      "03AD3A68D6E60D42373424DB12D41CEABD2A7D9ABDE08C12D1F5B1D8E48C5A2133",
      "0345C02D90A78E28F3F389EC4976F0A22B0A5F90D1001D5590EF3A643751949A7D",
      "03DA7902D8A0C28A748E6FF9C2EB95673D889642CB66FE0E2CED05D4089AD99F56",
      /* ochal, support, challenge, tcksum, body */
      NULL,
      NULL,
      "A1373035A003020101A123042103AD3A68D6E60D42373424DB12D41CEABD2A7D9ABDE0"
      "8C12D1F5B1D8E48C5A2133A20930073005A003020101",
      "45BA26F7829E728FB70CBC8C",
      "3075A00703050000000000A1143012A003020101A10B30091B077261656275726EA210"
      "1B0E415448454E412E4D49542E454455A3233021A003020102A11A30181B066B726274"
      "67741B0E415448454E412E4D49542E454455A511180F31393730303130313030303030"
      "305AA703020100A8053003020111",
      /* K'[0], K'[1], K'[2], K'[3] */
      "DA8BD16B066A4FFC1586F15DDDAC3F1E",
      "45EDFD5880239972F2A3DFA9CACCA35B",
      "DBD4F17960A39FF63F3637900D631B28",
      "F364E626CD13559A4E86DCE6F4D4EAD2"
    },
};

static krb5_context ctx;

static void
check(krb5_error_code code)
{
    const char *errmsg;

    if (code) {
        errmsg = krb5_get_error_message(ctx, code);
        assert(errmsg != NULL);
        abort();
    }
}

static void
check_key_equal(const krb5_keyblock *kb1, const krb5_keyblock *kb2)
{
    assert(kb1->enctype == kb2->enctype);
    assert(kb1->length == kb2->length);
    assert(memcmp(kb1->contents, kb2->contents, kb1->length) == 0);
}

static int
decode_hexchar(unsigned char c)
{
    if (isdigit(c))
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    abort();
}

static krb5_data *
decode_data(const char *s)
{
    size_t len = strlen(s), i;
    char *b;
    krb5_data *d;

    assert(len % 2 == 0);
    b = malloc(len / 2);
    assert(b != NULL);
    for (i = 0; i < len / 2; i++)
        b[i] = decode_hexchar(s[i * 2]) * 16 + decode_hexchar(s[i * 2 + 1]);
    d = malloc(sizeof(*d));
    assert(d != NULL);
    *d = make_data(b, len / 2);
    return d;
}

static krb5_keyblock *
decode_keyblock(krb5_enctype enctype, const char *s)
{
    krb5_data *d;
    krb5_keyblock *kb;

    d = decode_data(s);
    kb = malloc(sizeof(*kb));
    kb->magic = KV5M_KEYBLOCK;
    kb->enctype = enctype;
    kb->length = d->length;
    kb->contents = (uint8_t *)d->data;
    free(d);
    return kb;
}

static void
run_test(const struct test *t)
{
    groupstate *gstate;
    krb5_keyblock *ikey, *K0, *K1, *K2, *K3, *kb;
    krb5_data *x, *y, *T, *S, *K, *ochal, *support, *challenge, *tcksum, *body;
    krb5_data result, cksum;

    /* Decode hex strings into keyblocks and byte strings. */
    ikey = decode_keyblock(t->enctype, t->ikey);
    x = decode_data(t->x);
    y = decode_data(t->y);
    T = decode_data(t->T);
    S = decode_data(t->S);
    K = decode_data(t->K);
    ochal = (t->ochal != NULL) ? decode_data(t->ochal) : NULL;
    support = (t->support != NULL) ? decode_data(t->support) : NULL;
    challenge = decode_data(t->challenge);
    tcksum = decode_data(t->tcksum);
    body = decode_data(t->body);
    K0 = decode_keyblock(t->enctype, t->K0);
    K1 = decode_keyblock(t->enctype, t->K1);
    K2 = decode_keyblock(t->enctype, t->K2);
    K3 = decode_keyblock(t->enctype, t->K3);

    /* Verify KDC-side result computation. */
    check(group_init_state(ctx, TRUE, &gstate));
    check(group_result(ctx, gstate, t->group, ikey, x, S, &result));
    assert(data_eq(*K, result));
    krb5_free_data_contents(ctx, &result);
    group_free_state(gstate);

    /* Verify client-side result computation. */
    check(group_init_state(ctx, FALSE, &gstate));
    check(group_result(ctx, gstate, t->group, ikey, y, T, &result));
    assert(data_eq(*K, result));
    krb5_free_data_contents(ctx, &result);
    group_free_state(gstate);

    /* Verify transcript checksum. */
    cksum = empty_data();
    if (ochal != NULL)
        check(update_tcksum(ctx, &cksum, ikey, ochal));
    if (support != NULL)
        check(update_tcksum(ctx, &cksum, ikey, support));
    check(update_tcksum(ctx, &cksum, ikey, challenge));
    check(update_tcksum(ctx, &cksum, ikey, S));
    assert(data_eq(*tcksum, cksum));
    krb5_free_data_contents(ctx, &cksum);

    /* Verify derived keys. */
    check(derive_key(ctx, ikey, K, tcksum, body, 0, &kb));
    check_key_equal(K0, kb);
    krb5_free_keyblock(ctx, kb);
    check(derive_key(ctx, ikey, K, tcksum, body, 1, &kb));
    check_key_equal(K1, kb);
    krb5_free_keyblock(ctx, kb);
    check(derive_key(ctx, ikey, K, tcksum, body, 2, &kb));
    check_key_equal(K2, kb);
    krb5_free_keyblock(ctx, kb);
    check(derive_key(ctx, ikey, K, tcksum, body, 3, &kb));
    check_key_equal(K3, kb);
    krb5_free_keyblock(ctx, kb);

    krb5_free_keyblock(ctx, ikey);
    krb5_free_data(ctx, x);
    krb5_free_data(ctx, y);
    krb5_free_data(ctx, T);
    krb5_free_data(ctx, S);
    krb5_free_data(ctx, K);
    krb5_free_data(ctx, ochal);
    krb5_free_data(ctx, support);
    krb5_free_data(ctx, challenge);
    krb5_free_data(ctx, tcksum);
    krb5_free_data(ctx, body);
    krb5_free_keyblock(ctx, K0);
    krb5_free_keyblock(ctx, K1);
    krb5_free_keyblock(ctx, K2);
    krb5_free_keyblock(ctx, K3);
}

int
main()
{
    size_t i;

    check(krb5_init_context(&ctx));
    for (i = 0; i < sizeof(tests) / sizeof(*tests); i++)
        run_test(&tests[i]);
    krb5_free_context(ctx);
    return 0;
}
