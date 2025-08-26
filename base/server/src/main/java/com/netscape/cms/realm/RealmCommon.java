//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.realm.RealmBase;

/**
 * @author Endi S. Dewata
 */
public abstract class RealmCommon extends RealmBase {

    protected RealmConfig config;

    public RealmConfig getConfig() {
        return config;
    }

    public void setConfig(RealmConfig config) {
        this.config = config;
    }

    /**
     * Initialize RealmCommon object
     */
    @Override
    public void initInternal() throws LifecycleException {
        super.initInternal();
    }

    /**
     * Initialize realm
     */
    public void initRealm() throws Exception {
    }

    @Override
    public Principal authenticate(String username, String password) {
        return null;
    }

    @Override
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

    @Override
    public void stopInternal() throws LifecycleException {
        super.stopInternal();
    }
}
