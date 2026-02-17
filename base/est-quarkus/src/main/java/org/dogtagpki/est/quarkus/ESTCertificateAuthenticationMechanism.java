package org.dogtagpki.est.quarkus;

import jakarta.enterprise.context.ApplicationScoped;

import org.dogtagpki.server.quarkus.PKICertificateAuthenticationMechanism;

/**
 * EST Certificate Authentication Mechanism for Quarkus.
 *
 * Extends the shared PKICertificateAuthenticationMechanism to provide
 * EST-specific certificate authentication. The base class handles
 * SSL client certificate extraction and delegation to IdentityProvider.
 *
 * @author Fraser Tweedale (original)
 */
@ApplicationScoped
public class ESTCertificateAuthenticationMechanism extends PKICertificateAuthenticationMechanism {
    // Inherits all behavior from PKICertificateAuthenticationMechanism.
    // EST-specific customizations can be added here if needed.
}
