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
 * Provides profile policy configuration.
 */
public class ProfilePolicyConfig extends ConfigStore {

    public ProfilePolicyConfig() {
    }

    public ProfilePolicyConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfilePolicyConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns policy default configuration.
     */
    public PolicyDefaultConfig getPolicyDefaultConfig() {
        return getSubStore("default", PolicyDefaultConfig.class);
    }

    /**
     * Returns policy constraint configuration.
     */
    public PolicyConstraintConfig getPolicyConstraintConfig() {
        return getSubStore("constraint", PolicyConstraintConfig.class);
    }
}
