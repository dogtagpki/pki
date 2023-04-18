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

/**
 * Provides authz.* parameters.
 */
public class AuthorizationConfig extends ConfigStore {

    public final static String SOURCE_TYPE = "sourceType";
    public final static String SOURCE_TYPE_LDAP = "ldap";
    public final static String SOURCE_TYPE_XML = "web.xml";

    public AuthorizationConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthorizationConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns authz.sourceType parameter.
     */
    public String getSourceType() throws EBaseException {
        return getString(SOURCE_TYPE, SOURCE_TYPE_LDAP);
    }

    /**
     * Returns authz.instance.* parameters.
     */
    public AuthzManagersConfig getAuthzManagersConfig() {
        return getSubStore("instance", AuthzManagersConfig.class);
    }
}
