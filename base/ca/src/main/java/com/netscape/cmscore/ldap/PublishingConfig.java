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
 * Provides ca.publish.* parameters.
 */
public class PublishingConfig extends ConfigStore {

    public PublishingConfig() {
    }

    public PublishingConfig(ConfigStorage storage) {
        super(storage);
    }

    public PublishingConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns ca.publish.enable parameter.
     */
    public boolean isEnabled() throws EBaseException {
        return getBoolean("enable", false);
    }

    /**
     * Returns ca.publish.cert.enable parameter.
     */
    public boolean isCertEnabled() throws EBaseException {
        return getBoolean("cert.enable", true);
    }

    /**
     * Returns ca.publish.crl.enable parameter.
     */
    public boolean isCRLEnabled() throws EBaseException {
        return getBoolean("crl.enable", true);
    }

    /**
     * Returns ca.publish.createOwnDNEntry parameter.
     */
    public boolean getCreateOwnDNEntry() throws EBaseException {
        return getBoolean("createOwnDNEntry", false);
    }

    /**
     * Returns ca.publish.publisher.* parameters.
     */
    public PublishingPublisherConfig getPublisherConfig() {
        return getSubStore("publisher", PublishingPublisherConfig.class);
    }

    /**
     * Returns ca.publish.mapper.* parameters.
     */
    public PublishingMapperConfig getMapperConfig() {
        return getSubStore("mapper", PublishingMapperConfig.class);
    }

    /**
     * Returns ca.publish.rule.* parameters.
     */
    public PublishingRuleConfig getRuleConfig() {
        return getSubStore("rule", PublishingRuleConfig.class);
    }

    /**
     * Returns ca.publish.queue.* parameters.
     */
    public PublishingQueueConfig getQueueConfig() {
        return getSubStore("queue", PublishingQueueConfig.class);
    }

    /**
     * Returns ca.publish.ldappublish.* parameters.
     */
    public LDAPPublishingConfig getLDAPPublishingConfig() {
        return getSubStore("ldappublish", LDAPPublishingConfig.class);
    }
}
