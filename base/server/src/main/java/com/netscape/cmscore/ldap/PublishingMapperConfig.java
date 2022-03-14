//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldap;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class PublishingMapperConfig extends ConfigStore {

    public PublishingMapperConfig() {
    }

    public PublishingMapperConfig(ConfigStorage storage) {
        super(storage);
    }

    public PublishingMapperConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
