//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.jobs;

import java.util.Vector;

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

    /**
     * Returns jobsScheduler.job.<id>.* parameters.
     */
    public JobConfig getJobConfig(String id) {
        Vector<String> names = getSubStoreNames();
        if (!names.contains(id)) return null;
        return getSubStore(id, JobConfig.class);
    }

    /**
     * Creates jobsScheduler.job.<id>.* parameters.
     */
    public JobConfig createJobConfig(String id) {
        return makeSubStore(id, JobConfig.class);
    }

    /**
     * Removes jobsScheduler.job.<id>.* parameters.
     */
    public void removeJobConfig(String id) {
        removeSubStore(id);
    }
}
