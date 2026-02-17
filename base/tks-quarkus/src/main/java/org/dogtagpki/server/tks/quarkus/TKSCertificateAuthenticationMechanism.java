//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks.quarkus;

import jakarta.enterprise.context.ApplicationScoped;

import org.dogtagpki.server.quarkus.PKICertificateAuthenticationMechanism;

/**
 * TKS-specific certificate authentication mechanism for Quarkus.
 * Extends shared PKICertificateAuthenticationMechanism.
 */
@ApplicationScoped
public class TKSCertificateAuthenticationMechanism extends PKICertificateAuthenticationMechanism {
}
