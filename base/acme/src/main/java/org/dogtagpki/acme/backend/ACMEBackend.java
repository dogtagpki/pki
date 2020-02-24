//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.backend;

import java.math.BigInteger;

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

    public BigInteger issueCertificate(String csr) throws Exception {
        return null;
    }

    public String getCertificateChain(String certID) throws Exception {
        return null;
    }

    public void revokeCert(ACMERevocation revocation) throws Exception {
    }
}
