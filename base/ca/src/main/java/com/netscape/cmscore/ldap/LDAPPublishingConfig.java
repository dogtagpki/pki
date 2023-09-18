//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldap;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.Constants;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldapconn.LDAPConfig;

/**
 * Provides ca.publish.ldappublish.* parameters.
 */
public class LDAPPublishingConfig extends ConfigStore {

    public LDAPPublishingConfig() {
    }

    public LDAPPublishingConfig(ConfigStorage storage) {
        super(storage);
    }

    public LDAPPublishingConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns ca.publish.ldappublish.enable parameter.
     */
    public boolean isEnabled() throws EBaseException {
        return getBoolean("enable", false);
    }

    public String getEnable() throws EBaseException {
        return getString("enable", Constants.FALSE);
    }

    public void setEnable(String enable) throws EBaseException {
        putString("enable", enable);
    }

    /**
     * Returns ca.publish.ldappublish.ldap.* parameters.
     */
    public LDAPConfig getLDAPConfig() throws EBaseException {
        return getSubStore("ldap", LDAPConfig.class);
    }
}
