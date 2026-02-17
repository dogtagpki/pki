//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import jakarta.enterprise.context.ApplicationScoped;

import org.dogtagpki.server.quarkus.PKICertificateAuthenticationMechanism;

/**
 * CA-specific certificate authentication mechanism.
 */
@ApplicationScoped
public class CACertificateAuthenticationMechanism extends PKICertificateAuthenticationMechanism {
}
