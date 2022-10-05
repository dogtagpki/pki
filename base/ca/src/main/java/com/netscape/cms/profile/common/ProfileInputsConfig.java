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
 * Provides profile inputs configuration.
 */
public class ProfileInputsConfig extends ConfigStore {

    public ProfileInputsConfig() {
    }

    public ProfileInputsConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileInputsConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns profile input configuration.
     */
    public ProfileInputConfig getProfileInputConfig(String id) {
        return getSubStore(id, ProfileInputConfig.class);
    }

    /**
     * Removes profile input configuration.
     */
    public void removeProfileInputConfig(String id) {
        removeSubStore(id);
    }
}
