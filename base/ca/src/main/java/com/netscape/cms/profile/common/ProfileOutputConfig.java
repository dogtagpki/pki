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
 * Provides profile output configuration.
 */
public class ProfileOutputConfig extends ConfigStore {

    public ProfileOutputConfig() {
    }

    public ProfileOutputConfig(ConfigStorage storage) {
        super(storage);
    }

    public ProfileOutputConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
