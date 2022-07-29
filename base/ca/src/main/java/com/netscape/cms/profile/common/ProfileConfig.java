//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.profile.common;

/**
 * Provides profile configuration.
 */
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class ProfileConfig extends ConfigStore {

    public ProfileConfig() {
    }

    public ProfileConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
