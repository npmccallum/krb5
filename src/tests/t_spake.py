#!/usr/bin/python
from k5test import *

conf={'libdefaults': {'spake_preauth_groups': 'p256'}}
realm = K5Realm(create_user=False, create_host=False, krb5_conf=conf)
realm.run([kadminl, 'addprinc', '+requires_preauth', '-pw', 'pw', 'user'])

# Run cmd (with the specified input and expected code if given) with
# tracing enabled, and return the trace output as a string.
def trace(realm, cmd, input=None, expected_code=0):
    tracefile = os.path.join(realm.testdir, 'trace')
    if os.path.exists(tracefile):
        os.remove(tracefile)
    realm.run(['env', 'KRB5_TRACE=' + tracefile] + cmd, input=input,
              expected_code=expected_code)
    with open(tracefile, 'r') as f:
        lines = f.read().splitlines()
    for l in lines:
        output('trace: ' + l + '\n')
    return lines


# Fail if the entries in expected do not appear as partial matches of
# lines, in order.
def expect(lines, expected):
    ind = 0
    for l in lines:
        if expected[ind] in l:
            ind += 1
            if ind == len(expected):
                break
    if ind != len(expected):
        fail('Not seen in output: ' + expected[ind])


# Test a basic SPAKE preauth scenario with no optimizations.
expect(trace(realm, [kinit, 'user'], input='pw'),
       ('error from KDC: -1765328359/Additional pre-authentication required',
        'Selected etype info:',
        'Sending SPAKE support message',
        'error from KDC: -1765328293/More preauthentication data is required',
        'SPAKE challenge received with group 1',
        'Sending SPAKE response',
        'AS key determined by preauth:',
        'Decrypted AS reply'))

# Test an unsuccessful authentication.
expect(trace(realm, [kinit, 'user'], input='wrongpw', expected_code=1),
       ('error from KDC: -1765328359/Additional pre-authentication required',
        'Selected etype info:',
        'Sending SPAKE support message',
        'error from KDC: -1765328293/More preauthentication data is required',
        'SPAKE challenge received with group 1',
        'Sending SPAKE response',
        'error from KDC: -1765328353/Decrypt integrity check failed'))

# Test optimistic client preauth.        
expect(trace(realm, ['./icred', '-o', '-135', 'user', 'pw']),
       ('Sending SPAKE support message',
        'error from KDC: -1765328293/More preauthentication data is required',
        'Selected etype info:',
        'SPAKE challenge received with group 1',
        'Sending SPAKE response',
        'AS key determined by preauth:',
        'Decrypted AS reply'))

# Test KDC optimistic challenge (accepted by client).
oconf = {'libdefaults': {'spake_preauth_kdc_challenge': 'p256'}}
oenv = realm.special_env('ochal', True, krb5_conf=oconf)
realm.stop_kdc()
realm.start_kdc(env=oenv)
expect(trace(realm, [kinit, 'user'], input='pw'),
       ('error from KDC: -1765328359/Additional pre-authentication required',
        'Selected etype info:',
        'SPAKE challenge received with group 1',
        'Sending SPAKE response',
        'AS key determined by preauth:',
        'Decrypted AS reply'))

# Test KDC optimistic challenge (rejected by client).
rconf = {'libdefaults': {'spake_preauth_groups': 'testdonotuse,p256',
                         'spake_preauth_kdc_challenge': 'testdonotuse'}}
renv = realm.special_env('ochal', True, krb5_conf=rconf)
realm.stop_kdc()
realm.start_kdc(env=renv)
expect(trace(realm, [kinit, 'user'], input='pw'),
       ('error from KDC: -1765328359/Additional pre-authentication required',
        'Selected etype info:',
        'SPAKE challenge with group -1111 rejected',
        'Sending SPAKE support message',
        'error from KDC: -1765328293/More preauthentication data is required',
        'SPAKE challenge received with group 1',
        'Sending SPAKE response',
        'AS key determined by preauth:',
        'Decrypted AS reply'))

success('SPAKE pre-authentication tests')
