//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.authentication;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class AuthenticationConfig extends PropConfigStore {

    public AuthenticationConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthenticationConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
