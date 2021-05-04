//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldapconn;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class LDAPAuthenticationConfig extends PropConfigStore {

    public LDAPAuthenticationConfig(ConfigStorage storage) {
        super(storage);
    }

    public LDAPAuthenticationConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
