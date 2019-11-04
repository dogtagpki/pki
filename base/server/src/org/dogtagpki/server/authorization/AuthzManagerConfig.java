//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authorization;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldapconn.LDAPConfig;

public class AuthzManagerConfig extends PropConfigStore {

    public AuthzManagerConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthzManagerConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public LDAPConfig getLDAPConfig() {
        return getSubStore("ldap", LDAPConfig.class);
    }
}
