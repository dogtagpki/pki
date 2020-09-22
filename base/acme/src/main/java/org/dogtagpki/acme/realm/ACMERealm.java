//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;

/**
 * @author Endi S. Dewata
 */
public class ACMERealm {

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACMERealm.class);

    protected ACMERealmConfig config;

    public ACMERealmConfig getConfig() {
        return config;
    }

    public void setConfig(ACMERealmConfig config) {
        this.config = config;
    }

    public void init() throws Exception {
    }

    public Principal authenticate(String username, String password) throws Exception {
        return null;
    }

    public Principal authenticate(X509Certificate[] certs) throws Exception {
        return null;
    }

    public void close() throws Exception {
    }
}
