//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.common;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides profile policy set configuration.
 */
public class ProfilePolicySetConfig extends ConfigStore {

    public ProfilePolicySetConfig() {
    }

    public ProfilePolicySetConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfilePolicySetConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
