//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

import java.security.SecureRandom;
import java.text.DateFormat;
import java.text.SimpleDateFormat;

import org.apache.commons.lang3.RandomStringUtils;

/**
 * @author Endi S. Dewata
 * @author Alexander M. Scheel
 */
public class ACME {
    public final static DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");
    public static SecureRandom csprng;

    public static String randomAlphanumeric(int length) {
        if (csprng == null) {
            try {
                csprng = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");
            } catch (Exception e) {
                throw new RuntimeException("Must initialize JSS before calling ACME: " + e.getMessage(), e);
            }
        }

        /* Wrap RandomStringUtils.random instead of calling randomAlphanumeric
         * so that we control choice of RNG. */
        return RandomStringUtils.random(length, 0, 0, true, true, null, csprng);
    }
}
