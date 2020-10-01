//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.security;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class SSLConfig extends PropConfigStore {

    public SSLConfig() {
    }

    public SSLConfig(ConfigStorage storage) {
        super(storage);
    }

    public SSLConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
