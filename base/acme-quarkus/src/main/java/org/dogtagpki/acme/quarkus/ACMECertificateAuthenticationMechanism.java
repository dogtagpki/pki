//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.quarkus;

import jakarta.enterprise.context.ApplicationScoped;

import org.dogtagpki.server.quarkus.PKICertificateAuthenticationMechanism;

/**
 * ACME Certificate Authentication Mechanism for Quarkus.
 *
 * Extends the shared PKICertificateAuthenticationMechanism to provide
 * ACME-specific certificate authentication.
 */
@ApplicationScoped
public class ACMECertificateAuthenticationMechanism extends PKICertificateAuthenticationMechanism {
}
