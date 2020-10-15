//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme;

public class ValidationResult {
    private boolean ok;
    private ACMEError error;

    /* private constructor; use the static methods to ensure
     * that it is constructed either as "ok" with no error,
     * or "not ok" with a non-null error.
     */
    private ValidationResult(boolean ok, ACMEError error) {
        this.ok = ok;
        this.error = error;
    }

    public static ValidationResult ok() {
        return new ValidationResult(true, null);
    }

    public static ValidationResult fail(ACMEError error) {
        if (null == error) {
            throw new IllegalArgumentException("error cannot be null");
        }
        return new ValidationResult(false, error);
    }

    public boolean isOK() {
        return ok;
    }

    public ACMEError getError() {
        return error;
    }
}
