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
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.pkix.cms.SignedData;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.usrgrp.Certificates;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.usrgrp.ExactMatchCertUserLocator;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

/**
 * EST CMC Authentication.
 *
 * Extends CMCAuth to support EST-forwarded CMC requests with two-tier authentication:
 *
 * 1. EST subsystem authentication: Validates the EST subsystem's TLS client certificate
 *    using AgentCertAuth to ensure the EST instance is an authorized agent.
 *
 * 2. End-user authentication: The RA-authenticated client certificate (end-user's cert)
 *    is passed via HTTP header pki-est-client-cert. This authenticator verifies that
 *    the CMC request signer matches this RA-authenticated client certificate.
 *
 * The EST subsystem certificate is saved in SessionContext as "estSubsystemCert"
 * for auditing purposes later.
 *
 * @author cfu
 */
public class CMCAuthForEST extends CMCAuth {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMCAuthForEST.class);

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

        if (estClientCertObj instanceof String estClientCertB64) {
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

        // First, get and validate the EST subsystem's TLS client cert
        X509Certificate estSubsystemCert =
            (X509Certificate) auditContext.get(SessionContext.SSL_CLIENT_CERT);

        if (estSubsystemCert == null) {
            logger.error(method + "EST subsystem TLS client certificate not found");
            throw new EInvalidCredentials("EST subsystem TLS client certificate required");
        }

        logger.debug(method + "EST subsystem cert: " + estSubsystemCert.getSubjectDN().getName());

        // Validate EST subsystem cert using AgentCertAuth
        AuthSubsystem authSS = engine.getAuthSubsystem();
        AuthManager agentAuth = authSS.getAuthManager("AgentCertAuth");
        if (agentAuth == null) {
            logger.error(method + "AgentCertAuth authentication manager not found");
            throw new EBaseException("AgentCertAuth authentication manager not found");
        }

        AuthCredentials agentCred = new AuthCredentials();
        agentCred.set(AuthManager.CRED_SSL_CLIENT_CERT,
                     new X509Certificate[] { estSubsystemCert });

        try {
            agentAuth.authenticate(agentCred);
            logger.debug(method + "EST subsystem cert authenticated successfully");
        } catch (EBaseException e) {
            logger.error(method + "EST subsystem cert authentication failed: " + e.getMessage(), e);
            throw new EInvalidCredentials("EST subsystem authentication failed: " + e.getMessage());
        }

        // Save EST subsystem cert for auditing (before overwriting SSL_CLIENT_CERT)
        auditContext.put("estSubsystemCert", estSubsystemCert);

        // Now get the RA-authenticated client cert from header and replace SSL_CLIENT_CERT
        X509Certificate endUserCert = getClientCertificate(auditContext);
        if (endUserCert != null) {
            // Store it in the standard location that CMCAuth expects
            auditContext.put(SessionContext.SSL_CLIENT_CERT, endUserCert);
            logger.debug(method + "Set SSL_CLIENT_CERT to RA-authenticated client cert: " +
                        endUserCert.getSubjectDN().getName());
        }

        // Call parent CMCAuth.authenticate() which will now use the end-user cert
        return super.authenticate(credentials);
    }

    /**
     * Override verifySignerInfo to skip CA user database authentication for EST.
     *
     * For EST fullcmc enrollment, authentication is handled by:
     * 1. EST subsystem authentication (in authenticate() above) - proves request came from authorized EST
     * 2. CMC signature verification (done here) - proves client owns the private key
     * 3. Profile's RAHeaderClientCertSubjectNameConstraint - validates subject match and agent status
     *
     * The profile constraint already uses isAgentCert() to check if the client is a CA agent:
     * - If agent: allows any subject name
     * - If non-agent: requires subject to match client certificate
     *
     * Therefore, we don't need to authenticate against CA user database here.
     * This allows both agent and non-agent EST users to enroll via fullcmc.
     *
     * @param auditContext Session context
     * @param authToken Authentication token
     * @param cmcFullReq Signed CMC request
     * @return AuthToken if successful
     * @throws EBaseException if signature verification fails
     */
    @Override
    protected AuthToken verifySignerInfo(
            SessionContext auditContext,
            AuthToken authToken,
            SignedData cmcFullReq) throws EBaseException {

        String method = "CMCAuthForEST.verifySignerInfo: ";
        logger.debug(method + "begins");

        // Call parent's signature verification, but catch the exception
        // when it tries to authenticate against CA user database
        try {
            return super.verifySignerInfo(auditContext, authToken, cmcFullReq);
        } catch (EBaseException e) {
            // Check if this is a CA database authentication failure
            // (happens for both non-agent users and users not in CA database)
            String errorMsg = e.getMessage();
            if (errorMsg != null &&
                (errorMsg.contains("User not found") ||
                 errorMsg.contains("Invalid Credential") ||
                 errorMsg.contains("CMS_AUTHENTICATION_MANAGER_NOT_FOUND") ||
                 errorMsg.contains("cannot map certificate"))) {

                logger.debug(method + "CA database authentication skipped for EST enrollment");

                // Get the client certificate from session context
                X509Certificate clientCert =
                        (X509Certificate) auditContext.get(SessionContext.SSL_CLIENT_CERT);

                if (clientCert == null) {
                    throw new EInvalidCredentials("Missing client certificate for EST enrollment");
                }

                // Set the authenticated cert subject in the auth token
                // (needed by the profile processing)
                X500Name principal = (X500Name) clientCert.getSubjectDN();
                String subjectDN = principal.getName();
                logger.debug(method + "Setting authenticated cert subject: " + subjectDN);

                authToken.set(AuthToken.TOKEN_AUTHENTICATED_CERT_SUBJECT, subjectDN);

                BigInteger certSerial = clientCert.getSerialNumber();
                authToken.set(AuthManager.CRED_SSL_CLIENT_CERT, certSerial.toString());

                // Set USER_ID for audit logging (use cert subject since no CA database user)
                authToken.set(AuthToken.USER_ID, subjectDN);
                authToken.set("id", subjectDN);

                // Note: The profile's RAHeaderClientCertSubjectNameConstraint will run later
                // and will check if the client is an agent or validate subject name match
                return authToken;
            } else {
                // Some other error (signature verification failed, etc.)
                logger.error(method + "CMC signature verification failed: " + errorMsg);
                throw e;
            }
        }
    }
}
