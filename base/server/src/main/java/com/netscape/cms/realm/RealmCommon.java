//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;

import org.apache.catalina.realm.RealmBase;

/**
 * @author Endi S. Dewata
 */
public class RealmCommon extends RealmBase {

    protected RealmConfig config;

    public RealmConfig getConfig() {
        return config;
    }

    public void setConfig(RealmConfig config) {
        this.config = config;
    }

    public Principal authenticate(String username, String password) {
        return null;
    }

    public Principal authenticate(X509Certificate[] certs) {
        return null;
    }


    @Override
    protected String getPassword(String arg0) {
        return null;
    }

    @Override
    protected Principal getPrincipal(String arg0) {
        return null;
    }
}
