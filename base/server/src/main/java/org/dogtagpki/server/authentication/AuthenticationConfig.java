//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authentication;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides auths.* parameters.
 */
public class AuthenticationConfig extends ConfigStore {

    public AuthenticationConfig(ConfigStorage storage) {
        super(storage);
    }

    public AuthenticationConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns auths.instance.* parameters.
     */
    public AuthManagersConfig getAuthManagersConfig() {
        return getSubStore("instance", AuthManagersConfig.class);
    }

    /**
     * Returns auths.revocationChecking.* parameters.
     */
    public RevocationCheckingConfig getRevocationCheckingConfig() {
        return getSubStore("revocationChecking", RevocationCheckingConfig.class);
    }
}
