//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.security;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class SecureRandomConfig extends ConfigStore {

    public SecureRandomConfig() {
    }

    public SecureRandomConfig(ConfigStorage storage) {
        super(storage);
    }

    public SecureRandomConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getAlgorithm() throws EBaseException {
        return getString("algorithm", "pkcs11prng");
    }

    public String getProvider() throws EBaseException {
        return getString("provider", "Mozilla-JSS");
    }
}
