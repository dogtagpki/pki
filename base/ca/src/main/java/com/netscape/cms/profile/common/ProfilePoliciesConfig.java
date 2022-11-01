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
 * Provides profile policies configuration.
 */
public class ProfilePoliciesConfig extends ConfigStore {

    public ProfilePoliciesConfig() {
    }

    public ProfilePoliciesConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfilePoliciesConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
