//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.key;

/**
 *
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public final class KeyParameters {
    public static final String KEY_STATUS_ACTIVE = "active";
    public static final String KEY_STATUS_INACTIVE = "inactive";
    
    /* Data types */
    public static final String SYMMETRIC_KEY_TYPE = "symmetricKey";
    public static final String PASS_PHRASE_TYPE = "passPhrase";
    public static final String ASYMMETRIC_KEY_TYPE = "asymmetricKey";

    /* Symmetric Key Algorithms */
    public static final String DES_ALGORITHM = "DES";
    public static final String DESEDE_ALGORITHM = "DESede";
    public static final String DES3_ALGORITHM = "DES3";
    public static final String RC2_ALGORITHM = "RC2";
    public static final String RC4_ALGORITHM = "RC4";
    public static final String AES_ALGORITHM = "AES";

    // Asymmetric Key algorithms
    public static final String RSA_ALGORITHM = "RSA";
    public static final String DSA_ALGORITHM = "DSA";
    public static final String EC_ALGORITHM = "EC"; // Not supported yet.

}
