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
 * Provides jobsScheduler.* parameters.
 */
public class JobsSchedulerConfig extends ConfigStore {

    public JobsSchedulerConfig() {
    }

    public JobsSchedulerConfig(ConfigStorage storage) {
        super(storage);
    }

    public JobsSchedulerConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns jobsScheduler.impl.* parameters.
     */
    public JobPluginsConfig getJobPluginsConfig() {
        return getSubStore("impl", JobPluginsConfig.class);
    }

    /**
     * Returns jobsScheduler.job.* parameters.
     */
    public JobsConfig getJobsConfig() {
        return getSubStore("job", JobsConfig.class);
    }
}
