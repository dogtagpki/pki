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
 * Provides profile input configuration.
 */
public class ProfileInputConfig extends ConfigStore {

    public ProfileInputConfig() {
    }

    public ProfileInputConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileInputConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
