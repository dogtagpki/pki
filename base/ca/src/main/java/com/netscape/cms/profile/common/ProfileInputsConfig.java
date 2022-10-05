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
}
