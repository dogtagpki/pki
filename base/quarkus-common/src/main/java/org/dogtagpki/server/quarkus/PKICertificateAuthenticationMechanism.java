//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.net.ssl.SSLSession;

import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.CertificateAuthenticationRequest;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

import io.quarkus.security.credential.CertificateCredential;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;

/**
 * Shared Quarkus authentication mechanism for PKI subsystems.
 *
 * Extracts X.509 client certificates from the SSL/TLS session
 * and creates CertificateAuthenticationRequests for the identity
 * provider to validate.
 *
 * Subsystem-specific modules can extend this class to customize
 * certificate handling behavior.
 */
public class PKICertificateAuthenticationMechanism implements HttpAuthenticationMechanism {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(
            PKICertificateAuthenticationMechanism.class);

    @Override
    public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {

        SSLSession sslSession = context.request().sslSession();
        if (sslSession == null) {
            logger.debug("PKICertificateAuthenticationMechanism: No SSL session");
            return Uni.createFrom().nullItem();
        }

        try {
            Certificate[] peerCerts = sslSession.getPeerCertificates();
            if (peerCerts == null || peerCerts.length == 0) {
                logger.debug("PKICertificateAuthenticationMechanism: No peer certificates");
                return Uni.createFrom().nullItem();
            }

            X509Certificate clientCert = (X509Certificate) peerCerts[0];
            logger.debug("PKICertificateAuthenticationMechanism: Client certificate: {}",
                    clientCert.getSubjectX500Principal());

            CertificateCredential credential = new CertificateCredential(clientCert);
            CertificateAuthenticationRequest request = new CertificateAuthenticationRequest(credential);

            return identityProviderManager.authenticate(request);

        } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
            logger.debug("PKICertificateAuthenticationMechanism: Peer not verified: {}", e.getMessage());
            return Uni.createFrom().nullItem();
        }
    }

    @Override
    public Uni<ChallengeData> getChallenge(RoutingContext context) {
        return Uni.createFrom().item(new ChallengeData(401, "WWW-Authenticate", "Certificate"));
    }

    @Override
    public Set<Class<? extends io.quarkus.security.credential.Credential>> getCredentialTypes() {
        return Set.of(CertificateCredential.class);
    }

    @Override
    public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
        return Uni.createFrom().item(new HttpCredentialTransport(HttpCredentialTransport.Type.X509));
    }
}
