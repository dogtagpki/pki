//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authorization;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class AuthzManagerConfig extends PropConfigStore {

    public AuthzManagerConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthzManagerConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
