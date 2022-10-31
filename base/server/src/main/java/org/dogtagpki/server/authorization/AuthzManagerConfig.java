//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authorization;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldapconn.LDAPConfig;

/**
 * Provides authz.instance.<name>.* parameters.
 */
public class AuthzManagerConfig extends ConfigStore {

    public AuthzManagerConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthzManagerConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns authz.instance.<name>.pluginName parameter.
     */
    public String getPluginName() throws EBaseException {
        return getString("pluginName");
    }

    /**
     * Returns authz.instance.<name>.realm parameter.
     */
    public String getRealmName() throws EBaseException {
        return getString("realm", null);
    }

    /**
     * Returns authz.instance.<name>.ldap.* parameters.
     */
    public LDAPConfig getLDAPConfig() {
        return getSubStore("ldap", LDAPConfig.class);
    }
}
