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
 * Provides profile configuration.
 */
public class ProfileConfig extends ConfigStore {

    public ProfileConfig() {
    }

    public ProfileConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns profile inputs configuration.
     */
    public ProfileInputsConfig getProfileInputsConfig() {
        return getSubStore("input", ProfileInputsConfig.class);
    }
}
