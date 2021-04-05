//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldap;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class PublishingPublisherConfig extends PropConfigStore {

    public PublishingPublisherConfig() {
    }

    public PublishingPublisherConfig(ConfigStorage storage) {
        super(storage);
    }

    public PublishingPublisherConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
