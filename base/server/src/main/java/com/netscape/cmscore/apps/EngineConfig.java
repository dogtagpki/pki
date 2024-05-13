//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.apps;

import java.io.File;

import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.authorization.AuthorizationConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.dbs.DBSubsystem;
import com.netscape.cmscore.jobs.JobsSchedulerConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.logging.LoggingConfig;
import com.netscape.cmscore.security.JssSubsystemConfig;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmsutil.password.PasswordStoreConfig;
import com.netscape.cmsutil.password.PlainPasswordFile;

public class EngineConfig extends ConfigStore {

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

    public String getPasswordClass() throws EBaseException {
        return getString("passwordClass", PlainPasswordFile.class.getName());
    }

    public String getPasswordFile() throws EBaseException {
        String instanceDir = CMS.getInstanceDir();
        String confDir = instanceDir + File.separator + "conf";
        String defaultPasswordFile = confDir + File.separator + "password.conf";
        return getString("passwordFile", defaultPasswordFile);
    }

    public void setPasswordFile(String passwordFile) throws EBaseException {
        putString("passwordFile", passwordFile);
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

    /**
     * Returns internaldb.* parameters.
     */
    public LDAPConfig getInternalDBConfig() {
        return getSubStore("internaldb", LDAPConfig.class);
    }

    public SubsystemsConfig getSubsystemsConfig() {
        return getSubStore("subsystem", SubsystemsConfig.class);
    }

    /**
     * Returns auths.* parameters.
     */
    public AuthenticationConfig getAuthenticationConfig() {
        return getSubStore("auths", AuthenticationConfig.class);
    }

    /**
     * Returns authz.* parameters.
     */
    public AuthorizationConfig getAuthorizationConfig() {
        return getSubStore("authz", AuthorizationConfig.class);
    }

    /**
     * Returns dbs.* parameters.
     */
    public DatabaseConfig getDatabaseConfig() {
        return getSubStore(DBSubsystem.ID, DatabaseConfig.class);
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

    public PasswordStoreConfig getPasswordStoreConfig() throws EBaseException {

        PasswordStoreConfig config = new PasswordStoreConfig();
        config.setID(CMS.getInstanceID());
        config.setClassName(getPasswordClass());
        config.setFileName(getPasswordFile());

        return config;
    }

    public JssSubsystemConfig getJssSubsystemConfig() {
        return getSubStore("jss", JssSubsystemConfig.class);
    }

    /**
     * Returns jobsScheduler.* parameters.
     */
    public JobsSchedulerConfig getJobsSchedulerConfig() {
        return getSubStore("jobsScheduler", JobsSchedulerConfig.class);
    }

    /**
     * Returns log.* parameters.
     */
    public LoggingConfig getLoggingConfig() {
        return getSubStore("log", LoggingConfig.class);
    }

    /**
     * Returns keyWrap.useOAEP parameter.
     */
    public boolean getUseOAEPKeyWrap() throws EBaseException {
        return getBoolean("keyWrap.useOAEP", false);
    }
}
