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
 * Provides log.* parameters.
 */
public class LoggingConfig extends ConfigStore {

    public LoggingConfig() {
    }

    public LoggingConfig(ConfigStorage storage) {
        super(storage);
    }

    public LoggingConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns log.impl.* parameters.
     */
    public LoggerPluginsConfig getLoggerPluginsConfig() {
        return getSubStore("impl", LoggerPluginsConfig.class);
    }

    /**
     * Returns log.instance.* parameters.
     */
    public LoggersConfig getLoggersConfig() {
        return getSubStore("instance", LoggersConfig.class);
    }
}
