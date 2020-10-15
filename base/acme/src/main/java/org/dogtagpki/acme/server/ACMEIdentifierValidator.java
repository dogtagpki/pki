//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URI;
import java.net.URISyntaxException;

import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ValidationResult;

public class ACMEIdentifierValidator {

    /**
     * Validate syntax of identifier.
     *
     * @throws IllegalArgumentException if either type or value is null.
     * @return a result that is either OK, or a failure with an
     *         appropriate ACMEError attached.
     */
    public static ValidationResult validateSyntax(ACMEIdentifier id) {
        if (id.getType() == null) {
            throw new IllegalArgumentException("Programming error: type is null");
        } else if (id.getValue() == null) {
            throw new IllegalArgumentException("Programming error: value is null");
        }
        switch (id.getType()) {
            case "dns":
                return validateSyntaxDNS(id.getValue());
            default:
                ACMEError error = new ACMEError();
                error.setType("urn:ietf:params:acme:error:unsupportedIdentifier");
                error.setDetail("Unsupported identifier type: " + id.getType());
                return ValidationResult.fail(error);
        }
    }

    /**
     * Validate DNS identifier.
     *
     * Validates per Section 3.5 of RFC 1034 and Section 2.1 of
     * RFC 1123, and the additional rules of RFC 5280 Section 4.2.1.6.
     *
     * It is a precondition that type == "dns" and value != null.
     * Wildcard as first label is valid syntax.  Wildcard
     * _policy_ is checked elsewhere.
     */
    private static ValidationResult validateSyntaxDNS(String value) {
        String[] labels = value.split("\\.");

        if (labels.length < 1) {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:malformed");
            error.setDetail("dns identifier is empty");
            return ValidationResult.fail(error);
        }

        boolean first = true;
        for (String label : labels) {
            if (first) {
                first = false;
                if (label.equals("*") && labels.length > 1) {
                    // wildcard allowed in first label
                    // (as long as it isn't the only label)
                    continue;
                }
            }
            char[] cs = label.toCharArray();

            boolean allLetDigHyp = true;
            for (int j = 0; j < cs.length; j++) {
                if (!isLetDigHyp(cs[j])) {
                    allLetDigHyp = false;
                    break;
                }
            }

            if (
                cs.length < 1 || cs.length > 63     // length in bound
                || !isLetDig(cs[0])                 // first is letter or digit
                || !isLetDig(cs[cs.length - 1])     // last is letter or digit
                || !allLetDigHyp                    // all are letter, digit or hyphen
            ) {
                ACMEError error = new ACMEError();
                error.setType("urn:ietf:params:acme:error:malformed");
                error.setDetail("invalid label in dns identifier: `" + label + "`");
                return ValidationResult.fail(error);
            }
        }

        /* Extra check that URI class is happy with it */
        try {
            new URI("http", value, null, null);
        } catch (URISyntaxException e) {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:malformed");
            error.setDetail("Failed to construct URI for DNS name " + value);
            return ValidationResult.fail(error);
        }

        return ValidationResult.ok();
    }

    /* helper predicates for "dns" identifier validity */
    private static boolean isLetter(char c) { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'; }
    private static boolean isDigit(char c) { return c >= '0' && c <= '9'; }
    private static boolean isLetDig(char c) { return isLetter(c) || isDigit(c); }
    private static boolean isLetDigHyp(char c) { return isLetDig(c) || c == '-'; }

}
