//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.validator;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.dogtagpki.acme.ACMEAuthorization;
import org.dogtagpki.acme.ACMEChallenge;
import org.dogtagpki.acme.ACMEError;
import org.dogtagpki.acme.ACMEIdentifier;
import org.dogtagpki.acme.ValidationResult;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.OCTET_STRING;

/**
 * TLS-ALPN-01 challenge validator (RFC 8737).
 *
 * The validator connects to port 443 of the domain name being validated,
 * performs a TLS handshake offering only the "acme-tls/1" ALPN protocol
 * with SNI set to the domain name, then checks that the self-signed
 * certificate presented by the server:
 * - contains a subjectAltName extension with exactly one dNSName entry
 *   matching the domain name, and
 * - contains a critical acmeIdentifier extension whose value is the
 *   SHA-256 digest of the key authorization.
 *
 * The certificate is intentionally not validated against any trust anchor
 * since RFC 8737 requires the challenge certificate to be self-signed.
 *
 * Optional parameters in validators.conf:
 * - tls-alpn-01.timeout: connect/read timeout in milliseconds (default: 10000)
 */
public class TLSALPN01Validator extends ACMEValidator {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TLSALPN01Validator.class);

    // RFC 8737 Section 6.2: ALPN Protocol ID
    public static final String ACME_TLS_PROTOCOL = "acme-tls/1";

    // RFC 8737 Section 6.1: id-pe-acmeIdentifier
    public static final String ACME_IDENTIFIER_OID = "1.3.6.1.5.5.7.1.31";

    // RFC 8737 Section 3: the validation is done on port 443
    public static final int PORT = 443;

    public static final int DEFAULT_TIMEOUT = 10000; // milliseconds

    // subjectAltName GeneralName type for dNSName
    static final int SAN_DNS_NAME = 2;

    int timeout = DEFAULT_TIMEOUT;

    // not configurable: RFC 8737 mandates port 443
    int port = PORT;

    public TLSALPN01Validator() {
        super("TLS-ALPN-01", "tls-alpn-01");
    }

    @Override
    public void init() throws Exception {

        if (config == null) return;

        String value = config.getParameter("timeout");
        if (value != null) {
            timeout = Integer.parseInt(value);
            if (timeout <= 0) {
                throw new Exception("Invalid TLS-ALPN-01 timeout: " + value);
            }
        }

        logger.info("- timeout: " + timeout + " ms");
    }

    @Override
    public boolean isApplicable(ACMEAuthorization authorization) {

        // RFC 8737 Section 3:
        // The "tls-alpn-01" challenge MUST NOT be used to validate
        // wildcard domain names.
        Boolean wildcard = authorization.getWildcard();
        if (wildcard != null && wildcard) return false;

        // RFC 8737 only defines validation for "dns" identifiers
        ACMEIdentifier identifier = authorization.getIdentifier();
        return identifier != null && "dns".equals(identifier.getType());
    }

    /**
     * Generate the expected acmeIdentifier extension value (RFC 8737
     * Section 3): the DER encoding of an OCTET STRING containing the
     * SHA-256 digest of the key authorization.
     *
     * This method returns the DER-encoded extnValue exactly as returned
     * by X509Certificate.getExtensionValue(), i.e. the inner OCTET STRING
     * wrapped in the outer extnValue OCTET STRING. Since DER encoding
     * is unique, a byte comparison is sufficient.
     */
    public byte[] generateExtensionValue(String keyAuthorization) throws Exception {

        MessageDigest digest = MessageDigest.getInstance("SHA-256", "Mozilla-JSS");
        byte[] hash = digest.digest(keyAuthorization.getBytes("UTF-8"));

        OCTET_STRING innerExtnValue = new OCTET_STRING(hash);
        OCTET_STRING outerExtnValue = new OCTET_STRING(ASN1Util.encode(innerExtnValue));
        return ASN1Util.encode(outerExtnValue);
    }

    @Override
    public ValidationResult validateChallenge(
            ACMEAuthorization authorization,
            ACMEChallenge challenge) {

        ACMEIdentifier identifier = authorization.getIdentifier();
        String hostname = identifier.getValue();

        if (!isApplicable(authorization)) {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:rejectedIdentifier");
            error.setDetail("TLS-ALPN-01 challenge cannot be used to validate " + hostname);
            return ValidationResult.fail(error);
        }

        // RFC 8555 Section 8.1: Key Authorizations
        String accountID = authorization.getAccountID();
        String token = challenge.getToken();
        String keyAuthorization = token + "." + accountID;
        logger.info("Key authorization: " + keyAuthorization);

        byte[] expectedValue;
        try {
            expectedValue = generateExtensionValue(keyAuthorization);
        } catch (Exception e) {
            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:serverInternal");
            error.setDetail("Failed to construct acmeIdentifier value: " + e);
            return ValidationResult.fail(error);
        }

        String target = hostname + ":" + port;
        X509Certificate cert;

        try {
            cert = getCertificate(hostname);
        } catch (Exception e) {
            logger.info("Unable to validate TLS-ALPN-01 challenge: " + e.getMessage(), e);

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:tls");
            error.setDetail(
                    "Unable to validate TLS-ALPN-01 challenge at " + target + "\n" +
                    "Error: " + e.getMessage());

            return ValidationResult.fail(error);
        }

        try {
            validateCertificate(cert, hostname, expectedValue);

        } catch (Exception e) {
            logger.error("Invalid TLS-ALPN-01 certificate: " + e.getMessage());

            ACMEError error = new ACMEError();
            error.setType("urn:ietf:params:acme:error:incorrectResponse");
            error.setDetail(
                    "Unable to validate TLS-ALPN-01 challenge at " + target + ": "
                    + e.getMessage());

            return ValidationResult.fail(error);
        }

        return ValidationResult.ok();
    }

    /**
     * Connect to the host on port 443 with ALPN "acme-tls/1" and SNI set
     * to the hostname, and return the certificate presented by the host.
     */
    public X509Certificate getCertificate(String hostname) throws Exception {

        logger.info("Connecting to " + hostname + ":" + port);

        // Use JSSE to create TLS connection with ALPN.
        //
        // TODO: Replace JSSE with JSS once it supports ALPN.
        SSLContext context = SSLContext.getInstance("TLS", "SunJSSE");
        context.init(null, new TrustManager[] { new AcceptAllTrustManager() }, null);

        try (Socket socket = new Socket()) {

            socket.connect(new InetSocketAddress(hostname, port), timeout);
            socket.setSoTimeout(timeout);

            try (SSLSocket sslSocket = (SSLSocket) context.getSocketFactory()
                    .createSocket(socket, hostname, port, true)) {

                SSLParameters params = sslSocket.getSSLParameters();

                // RFC 8737 Section 3: use TLS 1.2 or higher
                //
                // Currently TLS 1.3 is disabled since JSSE will try to use
                // X25519MLKEM768 but for some reason it's invoking the KEM
                // decapsulator in JSS so the SSL handshake will fail:
                //
                //   org.mozilla.jss.pkcs11.PK11Exception: KEM algorithm not provided
                //           at org.mozilla.jss.provider.javax.crypto.JSSKEMDecapsulatorSpi.engineSecretSize(JSSKEMDecapsulatorSpi.java:54)
                //           at java.base/javax.crypto.KEM$Decapsulator.secretSize(KEM.java:414)
                //
                // The TLS 1.2 doesn't have this problem.
                //
                // TODO: allow TLS 1.3
                params.setProtocols(new String[] { "TLSv1.2" });

                // RFC 8737 Section 3: offer only the acme-tls/1 protocol
                params.setApplicationProtocols(new String[] { ACME_TLS_PROTOCOL });

                // RFC 8737 Section 3: SNI must be the domain name
                params.setServerNames(List.of(new SNIHostName(hostname)));

                // the challenge certificate is self-signed
                params.setEndpointIdentificationAlgorithm(null);

                sslSocket.setSSLParameters(params);
                sslSocket.startHandshake();

                String protocol = sslSocket.getApplicationProtocol();
                logger.info("Negotiated application protocol: " + protocol);

                // RFC 8737 Section 3: the server must negotiate acme-tls/1
                if (!ACME_TLS_PROTOCOL.equals(protocol)) {
                    throw new Exception("Server did not negotiate " + ACME_TLS_PROTOCOL + " protocol");
                }

                Certificate[] certs = sslSocket.getSession().getPeerCertificates();
                if (certs == null || certs.length == 0 || !(certs[0] instanceof X509Certificate)) {
                    throw new Exception("Server did not present an X.509 certificate");
                }

                X509Certificate cert = (X509Certificate) certs[0];
                logger.info("Certificate subject: " + cert.getSubjectX500Principal());

                return cert;
            }
        }
    }

    /**
     * Validate the challenge certificate per RFC 8737 Section 3.
     */
    public void validateCertificate(
            X509Certificate cert,
            String hostname,
            byte[] expectedValue) throws Exception {

        // The certificate must contain a subjectAltName extension
        // containing the dNSName being validated and no other entries.
        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
        if (sans == null || sans.size() != 1) {
            throw new Exception("Certificate must contain exactly one subjectAltName entry");
        }

        List<?> san = sans.iterator().next();
        Integer sanType = (Integer) san.get(0);
        Object sanValue = san.get(1);

        if (sanType != SAN_DNS_NAME
                || !(sanValue instanceof String)
                || !hostname.equalsIgnoreCase((String) sanValue)) {
            throw new Exception("Certificate subjectAltName does not match " + hostname);
        }

        // The acmeIdentifier extension must be critical.
        Set<String> criticalOIDs = cert.getCriticalExtensionOIDs();
        if (criticalOIDs == null) criticalOIDs = Collections.emptySet();

        if (!criticalOIDs.contains(ACME_IDENTIFIER_OID)) {
            throw new Exception("Certificate does not contain a critical acmeIdentifier extension");
        }

        // The extension value must match the key authorization digest.
        byte[] value = cert.getExtensionValue(ACME_IDENTIFIER_OID);
        if (value == null || !MessageDigest.isEqual(expectedValue, value)) {
            throw new Exception("Certificate acmeIdentifier does not match the expected key authorization");
        }
    }

    /**
     * Trust manager that accepts any server certificate. RFC 8737
     * challenge certificates are self-signed and are validated by
     * validateCertificate() instead of PKIX path validation.
     *
     * This extends X509ExtendedTrustManager so SunJSSE does not wrap it
     * with additional hostname or constraint checks.
     */
    static class AcceptAllTrustManager extends X509ExtendedTrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
