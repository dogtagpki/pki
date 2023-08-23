//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.common;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides profile configuration.
 */
public class ProfileConfig extends ConfigStore {

    public ProfileConfig() {
    }

    public ProfileConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getProfileName() throws EBaseException {
        return getString("name", "");
    }

    public void setProfileName(String name) {
        putString("name", name);
    }

    public String getDescription() throws EBaseException {
        return getString("desc", "");
    }

    public void setDescription(String description) {
        putString("desc", description);
    }

    public boolean getVisible() throws EBaseException {
        return getBoolean("visible", false);
    }

    public void setVisible(boolean visible) {
        putBoolean("visible", visible);
    }

    public boolean getEnable() throws EBaseException {
        return getBoolean("enable", false);
    }

    public String getEnableBy() throws EBaseException {
        return getString("enableBy", "");
    }

    public String getAuthenticatorID() throws EBaseException {
        return getString("auth.instance_id", null);
    }

    public void setAuthenticatorID(String id) {
        putString("auth.instance_id", id);
    }

    public String getAuthzAcl() throws EBaseException {
        return getString("authz.acl", "");
    }

    public void setAuthzAcl(String acl) {
        putString("authz.acl", acl);
    }

    public String getRenewal() throws EBaseException {
        return getString("renewal", "false");
    }

    public void setRenewal(boolean renewal) {
        putBoolean("renewal", renewal);
    }

    public String getXmlOutput() throws EBaseException {
        return getString("xmlOutput", "false");
    }

    public void setXMLOutput(boolean xmlOutput) {
        putBoolean("xmlOutput", xmlOutput);
    }

    /**
     * Returns profile inputs configuration.
     */
    public ProfileInputsConfig getProfileInputsConfig() {
        return getSubStore("input", ProfileInputsConfig.class);
    }

    /**
     * Returns profile outputs configuration.
     */
    public ProfileOutputsConfig getProfileOutputsConfig() {
        return getSubStore("output", ProfileOutputsConfig.class);
    }

    /**
     * Returns profile policy sets configuration.
     */
    public ProfilePolicySetsConfig getPolicySetsConfig() {
        return getSubStore("policyset", ProfilePolicySetsConfig.class);
    }
}
