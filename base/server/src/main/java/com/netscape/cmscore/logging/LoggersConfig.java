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
 * Provides log.instance.* parameters.
 */
public class LoggersConfig extends ConfigStore {

    public LoggersConfig() {
    }

    public LoggersConfig(ConfigStorage storage) {
        super(storage);
    }

    public LoggersConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
