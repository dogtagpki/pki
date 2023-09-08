//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldap;

import java.util.Collection;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides ca.publish.publisher.impl.* parameters.
 */
public class PublishingPublisherPluginsConfig extends ConfigStore {

    public PublishingPublisherPluginsConfig() {
    }

    public PublishingPublisherPluginsConfig(ConfigStorage storage) {
        super(storage);
    }

    public PublishingPublisherPluginsConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public Collection<String> getPluginIDs() {
        return getSubStoreNames();
    }

    public ConfigStore createPublisherPluginConfig(String id) {
        return makeSubStore(id);
    }

    public void removePublisherPluginConfig(String id) {
        removeSubStore(id);
    }
}
