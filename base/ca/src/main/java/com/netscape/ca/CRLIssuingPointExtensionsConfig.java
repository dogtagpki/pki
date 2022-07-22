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
 * Provides ca.crl.<name>.extension.* parameters.
 */
public class CRLIssuingPointExtensionsConfig extends ConfigStore {

    public CRLIssuingPointExtensionsConfig(ConfigStorage storage) {
        super(storage);
    }

    public CRLIssuingPointExtensionsConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
