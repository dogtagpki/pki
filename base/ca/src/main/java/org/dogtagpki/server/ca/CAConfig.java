//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import com.netscape.certsrv.security.SigningUnitConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmscore.ldap.PublishingConfig;

/**
 * Provides ca.* parameters.
 */
public class CAConfig extends ConfigStore {

    public CAConfig(ConfigStorage storage) {
        super(storage);
    }

    public CAConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public PublishingConfig getPublishingConfig() {
        return getSubStore("publish", PublishingConfig.class);
    }

    /**
     * Returns ca.signing.* parameters.
     */
    public SigningUnitConfig getSigningUnitConfig() {
        return getSubStore("signing", SigningUnitConfig.class);
    }

    /**
     * Returns ca.ocsp_signing.* parameters.
     */
    public SigningUnitConfig getOCSPSigningUnitConfig() {
        return getSubStore("ocsp_signing", SigningUnitConfig.class);
    }

    /**
     * Returns ca.crl_signing.* parameters.
     */
    public SigningUnitConfig getCRLSigningUnitConfig() {
        return getSubStore("crl_signing", SigningUnitConfig.class);
    }
}
