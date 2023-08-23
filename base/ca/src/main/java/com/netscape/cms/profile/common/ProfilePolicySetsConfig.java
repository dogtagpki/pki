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
 * Provides profile policy sets configuration.
 */
public class ProfilePolicySetsConfig extends ConfigStore {

    public ProfilePolicySetsConfig() {
    }

    public ProfilePolicySetsConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfilePolicySetsConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
