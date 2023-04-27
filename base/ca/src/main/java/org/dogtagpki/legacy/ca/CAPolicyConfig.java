//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.legacy.ca;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides ca.Policy.* parameters.
 */
public class CAPolicyConfig extends ConfigStore {

    public CAPolicyConfig(ConfigStorage storage) {
        super(storage);
    }

    public CAPolicyConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
