//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.authentication;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides auths.revocationChecking.* parameters.
 */
public class RevocationCheckingConfig extends ConfigStore {

    public RevocationCheckingConfig(ConfigStorage storage) {
        super(storage);
    }

    public RevocationCheckingConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns auths.revocationChecking.enabled parameter.
     */
    public boolean isEnabled() throws EBaseException {
        return getBoolean("enabled", false);
    }

    /**
     * Returns auths.revocationChecking.bufferSize parameter.
     */
    public int getBufferSize() throws EBaseException {
        return getInteger("bufferSize", 0);
    }

    /**
     * Returns auths.revocationChecking.validityInterval parameter.
     */
    public int getValidityInterval() throws EBaseException {
        return getInteger("validityInterval", 28800);
    }

    /**
     * Returns auths.revocationChecking.unknownStateInterval parameter.
     */
    public int getUnknownStateInterval() throws EBaseException {
        return getInteger("unknownStateInterval", 1800);
    }
}
