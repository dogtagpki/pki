// Copyright Red Hat, Inc.
// SPDX-License-Identifier: GPL-2.0-or-later

package org.dogtagpki.acme.caa;

import java.util.Locale;
import java.util.Objects;

/**
 * Represents a normalized absolute ASCII DNS domain name.
 * Normalization converts ASCII letters to lowercase; it does not add a root
 * dot, trim whitespace or convert internationalized names to ASCII.
 *
 * Examples:
 *
 * Input                         Result
 * "WWW.Example.COM."             "www.example.com."
 * "xn--bcher-kva.example."        unchanged (already ASCII)
 * "."                           unchanged (DNS root)
 *
 * Rejected input                Reason
 * "www.example.com"             missing final root dot
 * " www.example.com."           leading whitespace
 * "b\u00fccher.example."         requires IDNA conversion first
 * "*.example.com."              wildcard prefix is not part of the DNS name
 *
 * For "*.example.com", use CertificateName with:
 * - baseName: "example.com."
 * - wildcard: true
 *
 * This DNS lookup type permits underscore labels, such as "_service.example.".
 * CertificateName applies stricter checks for names being certified.
 */
public record DNSDomainName(String asciiAbsoluteName) {
    public DNSDomainName {
        Objects.requireNonNull(asciiAbsoluteName);
        if (asciiAbsoluteName.chars().anyMatch(value -> value > 127)) {
            throw new IllegalArgumentException("IDNA conversion must precede DNS name construction");
        }

        asciiAbsoluteName = asciiAbsoluteName.toLowerCase(Locale.ROOT);
        if (!asciiAbsoluteName.endsWith(".") || asciiAbsoluteName.length() > 254) {
            throw new IllegalArgumentException("Expected absolute ASCII DNS name");
        }

        if (!asciiAbsoluteName.equals(".")) {
            for (String label : asciiAbsoluteName.substring(0, asciiAbsoluteName.length() - 1).split("\\.", -1)) {
                if (label.isEmpty() || label.length() > 63 ||
                        !label.matches("[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?")) {
                    throw new IllegalArgumentException("Unsupported DNS label");
                }
            }
        }
    }
}
