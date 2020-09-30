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
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;

public class EngineConfig extends PropConfigStore {

    public EngineConfig() {
    }

    public EngineConfig(ConfigStorage storage) {
        super(storage);
    }

    public EngineConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getHostname() {
        try {
            return getString("machineName", "");
        } catch (EBaseException e) {
            throw new RuntimeException(e);
        }
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

    public LDAPConfig getInternalDBConfig() {
        return getSubStore("internaldb", LDAPConfig.class);
    }

    public SubsystemsConfig getSubsystemsConfig() {
        return getSubStore("subsystem", SubsystemsConfig.class);
    }

    public AuthenticationConfig getAuthenticationConfig() {
        return getSubStore("auths", AuthenticationConfig.class);
    }

    public AuthorizationConfig getAuthorizationConfig() {
        return getSubStore("authz", AuthorizationConfig.class);
    }

    public DatabaseConfig getDatabaseConfig() {
        return getSubStore("dbs", DatabaseConfig.class);
    }

    public PreOpConfig getPreOpConfig() {
        return getSubStore("preop", PreOpConfig.class);
    }

    public PKISocketConfig getSocketConfig() {
        return getSubStore("tcp", PKISocketConfig.class);
    }

    public UGSubsystemConfig getUGSubsystemConfig() {
        return getSubStore("usrgrp", UGSubsystemConfig.class);
    }
}
