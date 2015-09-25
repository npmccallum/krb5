/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
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
 * Declarations for clspakefactor plugin module implementors.
 *
 * The clspakefactor pluggable interface currently has only one supported major
 * version, which is 1.  Major version 1 has a current minor version number of
 * 1.
 *
 * Clspakefactor plugin modules should define a function named
 * clspakefactor_<modulename>_initvt, matching the signature:
 *
 *   krb5_error_code
 *   clspakefactor_modname_initvt(krb5_context context, int maj_ver,
 *                                int min_ver, krb5_plugin_vtable vtable);
 *
 * The initvt function should:
 *
 * - Check that the supplied maj_ver number is supported by the module, or
 *   return KRB5_PLUGIN_VER_NOTSUPP if it is not.
 *
 * - Cast the vtable pointer as appropriate for maj_ver:
 *     maj_ver == 1: Cast to krb5_clspakefactor_vtable
 *
 * - Initialize the methods of the vtable, stopping as appropriate for the
 *   supplied min_ver.  Optional methods may be left uninitialized.
 *
 * Memory for the vtable is allocated by the caller, not by the module.
 */

#ifndef KRB5_CLSPAKEFACTOR_PLUGIN_H
#define KRB5_CLSPAKEFACTOR_PLUGIN_H

#include <krb5/krb5.h>
#include <krb5/plugin.h>

/* An abstract type for clspakefactor module data. */
typedef struct krb5_clspakefactor_moddata_st *krb5_clspakefactor_moddata;

/*** Method type declarations ***/

/* Optional: Initialize module data. */
typedef krb5_error_code
(*krb5_clspakefactor_init_fn)(krb5_context context,
                              krb5_clspakefactor_moddata *data);

/* Optional: Release resources used by module data. */
typedef void
(*krb5_clspakefactor_fini_fn)(krb5_context context,
                              krb5_clspakefactor_moddata data);

/* clspakefactor vtable for major version 1. */
typedef struct krb5_clspakefactor_vtable_st {
    const char *name;           /* Mandatory: name of module. */
    krb5_clspakefactor_init_fn init;
    krb5_clspakefactor_fini_fn fini;
    /* Minor version 1 ends here. */
} *krb5_clspakefactor_vtable;

#endif /* KRB5_CLSPAKEFACTOR_PLUGIN_H */
