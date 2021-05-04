//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.ldap;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class PublishingConfig extends PropConfigStore {

    public PublishingConfig() {
    }

    public PublishingConfig(ConfigStorage storage) {
        super(storage);
    }

    public PublishingConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean getCreateOwnDNEntry() throws EBaseException {
        return getBoolean("createOwnDNEntry", false);
    }

    public PublishingPublisherConfig getPublisherConfig() {
        return getSubStore("publisher", PublishingPublisherConfig.class);
    }

    public PublishingMapperConfig getMapperConfig() {
        return getSubStore("mapper", PublishingMapperConfig.class);
    }

    public PublishingRuleConfig getRuleConfig() {
        return getSubStore("rule", PublishingRuleConfig.class);
    }
}
