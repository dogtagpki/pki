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
 * Provides log.instance.<id>.* parameters.
 */
public class LoggerConfig extends ConfigStore {

    public LoggerConfig() {
    }

    public LoggerConfig(ConfigStorage storage) {
        super(storage);
    }

    public LoggerConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
