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
 * Provides jobsScheduler.job.<id>.* parameters.
 */
public class JobConfig extends ConfigStore {

    public JobConfig() {
    }

    public JobConfig(ConfigStorage storage) {
        super(storage);
    }

    public JobConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
