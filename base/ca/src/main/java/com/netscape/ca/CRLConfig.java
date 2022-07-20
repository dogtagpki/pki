//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.ca;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides ca.crl.* parameters.
 */
public class CRLConfig extends ConfigStore {

    public CRLConfig(ConfigStorage storage) {
        super(storage);
    }

    public CRLConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns ca.crl.<name>.* parameters.
     */
    public CRLIssuingPointConfig getCRLIssuingPointConfig(String name) {
        return getSubStore(name, CRLIssuingPointConfig.class);
    }
}
