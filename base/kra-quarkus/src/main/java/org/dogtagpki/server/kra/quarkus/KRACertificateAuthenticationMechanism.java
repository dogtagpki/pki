//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra.quarkus;

import jakarta.enterprise.context.ApplicationScoped;

import org.dogtagpki.server.quarkus.PKICertificateAuthenticationMechanism;

/**
 * KRA Certificate Authentication Mechanism for Quarkus.
 *
 * Extends the shared PKICertificateAuthenticationMechanism to provide
 * KRA-specific certificate authentication.
 */
@ApplicationScoped
public class KRACertificateAuthenticationMechanism extends PKICertificateAuthenticationMechanism {
}
