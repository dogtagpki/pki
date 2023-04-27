//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.legacy.kra;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides kra.Policy.* parameters.
 */
public class KRAPolicyConfig extends ConfigStore {

    public KRAPolicyConfig(ConfigStorage storage) {
        super(storage);
    }

    public KRAPolicyConfig(String name, SimpleProperties source) {
        super(name, source);
    }
}
