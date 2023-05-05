//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.selftests;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides selftests.plugin.<plugin ID>.* parameters.
 */
public class SelfTestPluginConfig extends ConfigStore {

    public SelfTestPluginConfig(ConfigStorage storage) {
        super(storage);
    }

    public SelfTestPluginConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
