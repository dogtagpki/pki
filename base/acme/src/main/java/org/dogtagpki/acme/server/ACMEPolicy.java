//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.util.Date;

import org.dogtagpki.acme.ACMEIdentifier;

/**
 * This class includes mechanisms to enforce various policy and security
 * restrictions explicitly or implicitly enumerated by ACME.
 */
public class ACMEPolicy {

    private ACMEPolicyConfig config;

    public ACMEPolicy(ACMEPolicyConfig config) {
        this.config = config;
    }

    /**
     * Validates a record of the given type; throws an exception if it isn't
     * allowed by policy.
     */
    public void validateIdentifier(ACMEIdentifier identifier) throws Exception {
        if (!"dns".equals(identifier.getType())) {
            throw new Exception("Unsupported record type: " + identifier.getType());
        }

        validateWildcard(identifier.getValue());
    }

    /**
     * Validate DNS record from an ACME Order Identifier for wildcard
     * compliance.
     *
     * Throws an exception on malformed wildcards, but ignores non-wildcard
     * identifiers.
     */
    public void validateWildcard(String record) throws Exception {
        // RFC 8555 Section 7.1.3 describes a wildcard as:
        //    Any identifier of type "dns" in a newOrder request MAY have a
        //    wildcard domain name as its value.  A wildcard domain name
        //    consists of a single asterisk character followed by a single
        //    full stop character ("*.") followed by a domain name as defined
        //    for use in the Subject Alternate Name Extension by [RFC5280].
        //    An authorization returned by the server for a wildcard domain
        //    name identifier MUST NOT include the asterisk and full stop
        //    ("*.") prefix in the authorization identifier value.  The
        //    returned authorization MUST include the optional "wildcard"
        //    field, with a value of true.
        // Additionally, RFC 5280 describes literal domain names for use with
        // PKI; in particular, wildcards aren't permitted by RFC 5280, meaning
        // RFC 8555 wildcards must exist at the beginning and must not contain
        // multiple wildcards.
        if (!record.contains("*")) {
            // If the record doesn't contain any asterisks, it isn't a
            // wildcard and we can ignore it.
            return;
        }

        if (!record.startsWith("*.")) {
            // We know the record contains one wildcard. Because it isn't at
            // the beginning, the record is invalid.
            String msg = "ACME Order Identifier `" + record + "` contains a ";
            msg += "forbidden internal wildcard. It must contain only a ";
            msg += "starting wildcard (\"*.\")";
            throw new Exception(msg);
        }

        int wildcardLength = "*.".length();
        if (record.substring(wildcardLength).contains("*")) {
            // If there's another internal wildcard after the starting
            // wildcard, we must reject it as well.
            String msg = "ACME Order Identifier `" + record + "` contains ";
            msg += "multiple wildcards. It must contain only a starting ";
            msg += "wildcard (\"*.\")";
            throw new Exception(msg);
        }

        if (!config.getEnableWildcards()) {
            String msg = "ACME Order Identifier `" + record + "` disallowed ";
            msg += "by ACME Policy because it contains a wildcard.";
            throw new Exception(msg);
        }

        return;
    }

    public Date getNonceExpirationTime(Date currentTime) {
        return config.getRetention().getNonces().getExpirationTime(currentTime);
    }

    public Date getPendingAuthorizationExpirationTime(Date currentTime) {
        return config.getRetention().getPendingAuthorizations().getExpirationTime(currentTime);
    }

    public Date getInvalidAuthorizationExpirationTime(Date currentTime) {
        return config.getRetention().getInvalidAuthorizations().getExpirationTime(currentTime);
    }

    public Date getValidAuthorizationExpirationTime(Date currentTime) {
        return config.getRetention().getValidAuthorizations().getExpirationTime(currentTime);
    }

    public Date getPendingOrderExpirationTime(Date currentTime) {
        return config.getRetention().getPendingOrders().getExpirationTime(currentTime);
    }

    public Date getInvalidOrderExpirationTime(Date currentTime) {
        return config.getRetention().getInvalidOrders().getExpirationTime(currentTime);
    }

    public Date getReadyOrderExpirationTime(Date currentTime) {
        return config.getRetention().getReadyOrders().getExpirationTime(currentTime);
    }

    public Date getProcessingOrderExpirationTime(Date currentTime) {
        return config.getRetention().getProcessingOrders().getExpirationTime(currentTime);
    }

    public Date getValidOrderExpirationTime(Date currentTime) {
        return config.getRetention().getValidOrders().getExpirationTime(currentTime);
    }

    public Date getCertificateExpirationTime(Date currentTime) {
        return config.getRetention().getCertificates().getExpirationTime(currentTime);
    }
}
