//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmscore.security;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

public class RandomConfig extends PropConfigStore {

    public RandomConfig() {
    }

    public RandomConfig(ConfigStorage storage) {
        super(storage);
    }

    public RandomConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getAlgorithm() throws EBaseException {
        return getString("algorithm", "pkcs11prng");
    }

    public String getProvider() throws EBaseException {
        return getString("provider", "Mozilla-JSS");
    }
}
