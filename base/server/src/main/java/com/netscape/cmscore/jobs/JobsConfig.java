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
 * Provides jobsScheduler.job.* parameters.
 */
public class JobsConfig extends ConfigStore {

    public JobsConfig() {
    }

    public JobsConfig(ConfigStorage storage) {
        super(storage);
    }

    public JobsConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
