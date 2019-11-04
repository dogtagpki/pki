//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authentication;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldapconn.LDAPConfig;

public class AuthManagerConfig extends PropConfigStore {

    public AuthManagerConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthManagerConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public LDAPConfig getLDAPConfig() {
        return getSubStore("ldap", LDAPConfig.class);
    }
}
