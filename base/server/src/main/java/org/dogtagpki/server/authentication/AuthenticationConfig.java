//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authentication;

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

    public AuthManagersConfig getAuthManagersConfig() {
        return getSubStore("instance", AuthManagersConfig.class);
    }
}
