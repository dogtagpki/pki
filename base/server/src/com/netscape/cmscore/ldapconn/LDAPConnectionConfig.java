//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldapconn;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class LDAPConnectionConfig extends PropConfigStore {

    public LDAPConnectionConfig(ConfigStorage storage) {
        super(storage);
    }

    public LDAPConnectionConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
