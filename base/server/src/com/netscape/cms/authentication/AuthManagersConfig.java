//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.authentication;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class AuthManagersConfig extends PropConfigStore {

    public AuthManagersConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthManagersConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
