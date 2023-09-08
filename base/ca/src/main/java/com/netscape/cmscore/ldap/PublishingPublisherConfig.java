//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldap;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides ca.publish.publisher.* parameters.
 */
public class PublishingPublisherConfig extends ConfigStore {

    public PublishingPublisherConfig() {
    }

    public PublishingPublisherConfig(ConfigStorage storage) {
        super(storage);
    }

    public PublishingPublisherConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns ca.publish.publisher.impl.* parameters.
     */
    public PublishingPublisherPluginsConfig getPublisherPluginsConfig() {
        return getSubStore("impl", PublishingPublisherPluginsConfig.class);
    }
}
