// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2025 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.authentication;

import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;

import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;

/**
 * EST CMC Authentication.
 *
 * Extends CMCAuth to support EST-forwarded CMC requests where the actual
 * EST client certificate is passed via HTTP header pki-est-client-cert
 * instead of via TLS (SessionContext.SSL_CLIENT_CERT).
 *
 * The TLS connection between EST and CA uses the EST subsystem certificate,
 * but the CMC request is signed by the EST client's certificate. This
 * authenticator verifies that the CMC signer matches the EST client cert
 * from the header.
 *
 * @author cfu
 */
public class CMCAuthForEST extends CMCAuth {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMCAuthForEST.class);

    public static final String EST_CLIENT_CERT_HEADER = "pki-est-client-cert";

    /**
     * Gets the client certificate for CMC authentication.
     *
     * For EST-forwarded requests, this reads the EST client certificate from
     * the pki-est-client-cert HTTP header instead of from the TLS session context.
     *
     * @param auditContext The session context
     * @return The EST client certificate, or null if not available
     * @throws RuntimeException if the certificate header exists but cannot be decoded/parsed
     */
    protected X509Certificate getClientCertificate(SessionContext auditContext) {
        String method = "CMCAuthForEST.getClientCertificate: ";

        // First try to get EST client cert from HTTP header
        Object estClientCertObj = auditContext.get(EST_CLIENT_CERT_HEADER);

        if (estClientCertObj != null && estClientCertObj instanceof String) {
            String estClientCertB64 = (String) estClientCertObj;
            logger.debug(method + "Found pki-est-client-cert header");

            try {
                // Decode base64 certificate
                byte[] certBytes = Utils.base64decode(estClientCertB64);

                // Parse certificate as JSS X509CertImpl (required for CMCAuth)
                X509CertImpl cert = new X509CertImpl(certBytes);

                logger.debug(method + "Successfully decoded EST client certificate: " +
                    cert.getSubjectDN().getName());
                return cert;

            } catch (Exception e) {
                // Certificate exists but cannot be parsed - this is a real error
                logger.error(method + "Failed to decode EST client certificate from header: " +
                    e.getMessage(), e);
                throw new RuntimeException("Failed to decode EST client certificate", e);
            }
        }

        // No EST client certificate header found
        logger.debug(method + "No pki-est-client-cert header found");
        return null;
    }

    @Override
    public AuthToken authenticate(AuthCredentials credentials)
            throws EBaseException {

        String method = "CMCAuthForEST.authenticate: ";
        logger.debug(method + "begins");

        // Get the session context which may contain the EST client cert header
        SessionContext auditContext = SessionContext.getExistingContext();

        // Store the client certificate in the session context for CMCAuth to use
        X509Certificate clientCert = getClientCertificate(auditContext);
        if (clientCert != null) {
            // Store it in the standard location that CMCAuth expects
            auditContext.put(SessionContext.SSL_CLIENT_CERT, clientCert);
            logger.debug(method + "Set SSL_CLIENT_CERT to: " + clientCert.getSubjectDN().getName());
        }

        // Call parent CMCAuth.authenticate() which will now use our client cert
        return super.authenticate(credentials);
    }
}
