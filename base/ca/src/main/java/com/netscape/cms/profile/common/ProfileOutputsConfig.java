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
 * Provides profile outputs configuration.
 */
public class ProfileOutputsConfig extends ConfigStore {

    public ProfileOutputsConfig() {
    }

    public ProfileOutputsConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileOutputsConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
