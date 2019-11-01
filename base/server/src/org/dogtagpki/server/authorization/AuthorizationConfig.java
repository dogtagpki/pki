//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authorization;

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

    public AuthzManagersConfig getAuthzManagersConfig() {

        String fullname = getFullName("instance");
        String reference = mSource.get(fullname);

        if (reference == null) {
            return new AuthzManagersConfig(fullname, mSource);

        } else {
            return new AuthzManagersConfig(reference, mSource);
        }
    }
}
