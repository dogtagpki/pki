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

        // dns identifiers must be hostnames, not IP literals (RFC 8555).
        // Accepting IPs enables SSRF via HTTP-01 (see dogtagpki/pki#5407).
        if (isIpLiteral(value)) {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:malformed");
            error.setDetail("DNS identifier must not be an IP address: " + value);
            return ValidationResult.fail(error);
        }

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
            if (value.startsWith("*.")) {
                String domain = value.substring(2); // Remove the leading "*."
                new URI("http", domain, null, null);
            } else {
                new URI("http", value, null, null);
            }
        } catch (URISyntaxException e) {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:malformed");
            error.setDetail("Failed to construct URI for DNS name " + value);
            return ValidationResult.fail(error);
        }

        return ValidationResult.ok();
    }

    /**
     * True if value is an IPv4/IPv6 literal (optional [], optional leading "*.").
     * Wildcard is stripped because newOrder removes "*." before HTTP-01.
     * Parsing is lexical only (no InetAddress/DNS) and covers the decimal IPv4
     * forms Java accepts (d, d.d, d.d.d, d.d.d.d).
     */
    static boolean isIpLiteral(String value) {
        String host = value.startsWith("*.") ? value.substring(2) : value;
        if (host.startsWith("[") && host.endsWith("]") && host.length() > 2) {
            host = host.substring(1, host.length() - 1);
        }
        if (host.indexOf(':') >= 0) {
            return isIpv6Literal(host);
        }
        return isIpv4Literal(host);
    }

    /**
     * Match Java Inet4Address decimal IPv4 text forms (historical inet_aton style):
     * d (32-bit), d.d (8+24), d.d.d (8+8+16), or d.d.d.d (four bytes).
     * Digits only; leading zeros allowed. See java.net.Inet4Address.
     */
    private static boolean isIpv4Literal(String host) {
        if (host.isEmpty()) {
            return false;
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c != '.' && (c < '0' || c > '9')) {
                return false;
            }
        }
        String[] parts = host.split("\\.", -1);
        if (parts.length < 1 || parts.length > 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty()) {
                return false;
            }
        }
        switch (parts.length) {
            case 1: // d -> 32-bit value (e.g. 2130706433)
                return inRange(parts[0], 0xFFFFFFFFL);
            case 2: // d.d -> 8-bit + 24-bit (e.g. 127.1)
                return inRange(parts[0], 255) && inRange(parts[1], 0xFFFFFFL);
            case 3: // d.d.d -> 8-bit + 8-bit + 16-bit (e.g. 127.0.1)
                return inRange(parts[0], 255) && inRange(parts[1], 255)
                        && inRange(parts[2], 0xFFFFL);
            case 4: // d.d.d.d -> four 8-bit octets (e.g. 127.0.0.1)
                return inRange(parts[0], 255) && inRange(parts[1], 255)
                        && inRange(parts[2], 255) && inRange(parts[3], 255);
            default:
                return false;
        }
    }

    private static boolean inRange(String part, long max) {
        try {
            long value = Long.parseLong(part);
            return value >= 0 && value <= max;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Simplified lexical IPv6 text check (RFC 4291 / RFC 5952 style):
     * hex digits and ':', at most one "::" compression, optional dotted IPv4
     * tail for mapped forms (e.g. ::ffff:127.0.0.1). Not a full RFC parser.
     */
    private static boolean isIpv6Literal(String host) {
        int colons = 0;
        int doubleColon = 0;
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (c == ':') {
                colons++;
                // "::" may appear at most once
                if (i + 1 < host.length() && host.charAt(i + 1) == ':') {
                    doubleColon++;
                    i++;
                    colons++;
                }
            } else if (!isHex(c) && c != '.') {
                // '.' only for IPv4-mapped / IPv4-compatible tails
                return false;
            }
        }
        // At least one ":" pair worth of colons; reject multiple "::"
        if (colons < 2 || doubleColon > 1) {
            return false;
        }
        // If an IPv4 tail is present after the last ':', validate it as IPv4
        int lastColon = host.lastIndexOf(':');
        if (lastColon >= 0 && host.indexOf('.', lastColon) >= 0) {
            return isIpv4Literal(host.substring(lastColon + 1));
        }
        return true;
    }

    private static boolean isHex(char c) {
        return c >= '0' && c <= '9'
                || c >= 'a' && c <= 'f'
                || c >= 'A' && c <= 'F';
    }

    /* helper predicates for "dns" identifier validity */
    private static boolean isLetter(char c) { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'; }
    private static boolean isDigit(char c) { return c >= '0' && c <= '9'; }
    private static boolean isLetDig(char c) { return isLetter(c) || isDigit(c); }
    private static boolean isLetDigHyp(char c) { return isLetDig(c) || c == '-'; }

}
