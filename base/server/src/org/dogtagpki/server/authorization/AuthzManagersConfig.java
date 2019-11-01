//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authorization;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class AuthzManagersConfig extends PropConfigStore {

    public AuthzManagersConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthzManagersConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
