//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.apps;

import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.authorization.AuthorizationConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.ldapconn.LDAPConfig;

public class EngineConfig extends PropConfigStore {

    public EngineConfig(ConfigStorage storage) {
        super(storage);
    }

    public String getHostname() throws EBaseException {
        return getString("machineName");
    }

    public void setHostname(String hostname) throws EBaseException {
        putString("machineName", hostname);
    }

    public String getInstanceID() throws EBaseException {
        return getString("instanceId");
    }

    public void setInstanceID(String instanceID) throws EBaseException {
        putString("instanceId", instanceID);
    }

    public String getInstanceDir() throws EBaseException {
        return getString("instanceRoot");
    }

    public void setInstanceDir(String instanceDir) {
        putString("instanceRoot", instanceDir);
    }

    public String getType() throws EBaseException {
        return getString("cs.type");
    }

    public void setType(String type) throws EBaseException {
        putString("cs.type", type);
    }

    public int getState() throws EBaseException {
        return getInteger("cs.state");
    }

    public void setState(int state) {
        putInteger("cs.state", state);
    }

    public LDAPConfig getInternalDatabase() {

        String fullname = getFullName("internaldb");
        String reference = mSource.get(fullname);

        if (reference == null) {
            return new LDAPConfig(fullname, mSource);

        } else {
            return new LDAPConfig(reference, mSource);
        }
    }

    public SubsystemsConfig getSubsystemsConfig() {

        String fullname = getFullName("subsystem");
        String reference = mSource.get(fullname);

        if (reference == null) {
            return new SubsystemsConfig(fullname, mSource);

        } else {
            return new SubsystemsConfig(reference, mSource);
        }
    }

    public AuthenticationConfig getAuthenticationConfig() {

        String fullname = getFullName("auths");
        String reference = mSource.get(fullname);

        if (reference == null) {
            return new AuthenticationConfig(fullname, mSource);

        } else {
            return new AuthenticationConfig(reference, mSource);
        }
    }

    public AuthorizationConfig getAuthorizationConfig() {

        String fullname = getFullName("authz");
        String reference = mSource.get(fullname);

        if (reference == null) {
            return new AuthorizationConfig(fullname, mSource);

        } else {
            return new AuthorizationConfig(reference, mSource);
        }
    }

    public DatabaseConfig getDatabaseConfig() {

        String fullname = getFullName("dbs");
        String reference = mSource.get(fullname);

        if (reference == null) {
            return new DatabaseConfig(fullname, mSource);

        } else {
            return new DatabaseConfig(reference, mSource);
        }
    }
}
