//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ocsp;

import com.netscape.certsrv.security.SigningUnitConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides ocsp.* parameters.
 */
public class OCSPConfig extends ConfigStore {

    public OCSPConfig(ConfigStorage storage) {
        super(storage);
    }

    public OCSPConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns ocsp.signing.* parameters.
     */
    public SigningUnitConfig getSigningUnitConfig() {
        return getSubStore("signing", SigningUnitConfig.class);
    }
}
