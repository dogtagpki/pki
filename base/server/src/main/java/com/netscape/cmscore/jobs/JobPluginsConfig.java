//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.jobs;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides jobsScheduler.impl.* parameters.
 */
public class JobPluginsConfig extends ConfigStore {

    public JobPluginsConfig() {
    }

    public JobPluginsConfig(ConfigStorage storage) {
        super(storage);
    }

    public JobPluginsConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
