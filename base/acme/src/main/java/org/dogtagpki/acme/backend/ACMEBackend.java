//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.backend;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.NotImplementedException;
import org.dogtagpki.acme.ACMERevocation;

/**
 * @author Endi S. Dewata
 */
public class ACMEBackend {

    protected ACMEBackendConfig config;

    public ACMEBackendConfig getConfig() {
        return config;
    }

    public void setConfig(ACMEBackendConfig config) {
        this.config = config;
    }

    public void init() throws Exception {
    }

    public void close() throws Exception {
    }

    /**
     * This method generates a unique ID for a certificate.
     *
     * By default this method will return the base64-encoded serial number
     * of the certificate. This method may be overridden to generate a backend-
     * specific unique ID for the certificate.
     *
     * @param cert Certificate.
     * @return Unique ID for the certificate.
     * @throws Exception
     */
    public String getCertificateID(X509Certificate cert) throws Exception {
        BigInteger serialNumber = cert.getSerialNumber();
        return Base64.encodeBase64URLSafeString(serialNumber.toByteArray());
    }

    /**
     * This method generates a certificate using the provided certificate signing request,
     * then returns the new certificate.
     *
     * @param csr Certificate signing request.
     * @return Certificate.
     * @throws Exception
     */
    public X509Certificate generateCertificate(String csr) throws Exception {
        throw new NotImplementedException();
    }

    /**
     * This method generates a certificate using the provided certificate signing request,
     * then returns a unique ID for the new certificate.
     *
     * @param csr Certificate signing request.
     * @return Unique ID for the new certificate.
     * @throws Exception
     */
    public String issueCertificate(String csr) throws Exception {
        X509Certificate cert = generateCertificate(csr);
        return getCertificateID(cert);
    }

    public String getCertificateChain(String certID) throws Exception {
        throw new NotImplementedException();
    }

    public void revokeCert(ACMERevocation revocation) throws Exception {
        throw new NotImplementedException();
    }
}
