//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.kra;

import org.dogtagpki.legacy.kra.KRAPolicyConfig;

import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.kra.KeyRecoveryAuthority;

public class KRAConfig extends ConfigStore {

    public KRAConfig(ConfigStorage storage) {
        super(storage);
    }

    public KRAConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns kra.Policy.* parameters.
     */
    public KRAPolicyConfig getPolicyConfig() {
        return getSubStore(KeyRecoveryAuthority.PROP_POLICY, KRAPolicyConfig.class);
    }
}
