//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp.quarkus;

import java.security.cert.X509Certificate;

import jakarta.enterprise.context.ApplicationScoped;

import org.dogtagpki.server.quarkus.PKIIdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.realm.PKIPrincipalCore;

/**
 * OCSP-specific identity provider for certificate authentication.
 *
 * Extends the shared PKIIdentityProvider from pki-quarkus-common.
 */
@ApplicationScoped
public class OCSPIdentityProvider extends PKIIdentityProvider {

    private static final Logger logger = LoggerFactory.getLogger(OCSPIdentityProvider.class);

    @Override
    protected PKIPrincipalCore authenticateCertificate(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        String cn = extractCN(dn);
        String principalName = cn != null ? cn : dn;

        logger.info("OCSPIdentityProvider: Authenticated certificate for: {}", principalName);

        return new PKIPrincipalCore(principalName, null, java.util.List.of("ocsp-client"));
    }
}
