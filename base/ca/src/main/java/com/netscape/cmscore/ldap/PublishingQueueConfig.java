//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldap;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides ca.publish.queue.* parameters.
 */
public class PublishingQueueConfig extends ConfigStore {

    public PublishingQueueConfig() {
    }

    public PublishingQueueConfig(ConfigStorage storage) {
        super(storage);
    }

    public PublishingQueueConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns ca.publish.queue.enable parameter.
     */
    public boolean isEnabled() throws EBaseException {
        return getBoolean("enable", false);
    }

    /**
     * Returns ca.publish.queue.priorityLevel parameter.
     */
    public int getPriorityLevel() throws EBaseException {
        return getInteger("priorityLevel", 0);
    }

    /**
     * Returns ca.publish.queue.maxNumberOfThreads parameter.
     */
    public int getMaxNumberOfThreads() throws EBaseException {
        return getInteger("maxNumberOfThreads", 1);
    }

    /**
     * Returns ca.publish.queue.pageSize parameter.
     */
    public int getPageSize() throws EBaseException {
        return getInteger("pageSize", 100);
    }

    /**
     * Returns ca.publish.queue.saveStatus parameter.
     */
    public int getSaveStatus() throws EBaseException {
        return getInteger("saveStatus", 0);
    }
}
