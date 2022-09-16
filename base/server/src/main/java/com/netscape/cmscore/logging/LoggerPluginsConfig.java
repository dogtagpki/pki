//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.logging;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides log.impl.* parameters.
 */
public class LoggerPluginsConfig extends ConfigStore {

    public LoggerPluginsConfig() {
    }

    public LoggerPluginsConfig(ConfigStorage storage) {
        super(storage);
    }

    public LoggerPluginsConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
