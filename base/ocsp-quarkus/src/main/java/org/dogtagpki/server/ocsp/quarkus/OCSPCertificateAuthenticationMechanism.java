//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import jakarta.enterprise.context.ApplicationScoped;

import org.dogtagpki.server.quarkus.PKICertificateAuthenticationMechanism;

/**
 * OCSP Certificate Authentication Mechanism for Quarkus.
 *
 * Extends the shared PKICertificateAuthenticationMechanism to provide
 * OCSP-specific certificate authentication.
 */
@ApplicationScoped
public class OCSPCertificateAuthenticationMechanism extends PKICertificateAuthenticationMechanism {
}
