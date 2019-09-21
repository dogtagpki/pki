//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.authorization;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class AuthorizationConfig extends PropConfigStore {

    public AuthorizationConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthorizationConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
