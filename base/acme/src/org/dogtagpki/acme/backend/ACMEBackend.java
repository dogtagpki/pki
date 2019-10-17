//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.backend;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

import org.dogtagpki.acme.JWS;

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

    public String generateCertificate(String csr) throws Exception {
        return null;
    }

    public Response getCertificateChain(
            UriInfo uriInfo,
            String certID) throws Exception {
        return null;
    }

    public Response revokeCert(
            UriInfo uriInfo,
            JWS jws) throws Exception {
        return null;
    }
}
