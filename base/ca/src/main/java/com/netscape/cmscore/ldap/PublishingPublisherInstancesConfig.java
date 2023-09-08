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
 * Provides ca.publish.publisher.instance.* parameters.
 */
public class PublishingPublisherInstancesConfig extends ConfigStore {

    public PublishingPublisherInstancesConfig() {
    }

    public PublishingPublisherInstancesConfig(ConfigStorage storage) {
        super(storage);
    }

    public PublishingPublisherInstancesConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public Collection<String> getInstanceIDs() {
        return getSubStoreNames();
    }

    public ConfigStore getPublisherInstanceConfig(String id) {
        return getSubStore(id);
    }

    public ConfigStore createPublisherInstanceConfig(String id) {
        return makeSubStore(id);
    }

    public void removePublisherInstanceConfig(String id) {
        removeSubStore(id);
    }
}
