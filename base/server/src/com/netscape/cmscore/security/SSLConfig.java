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

public class SSLConfig extends PropConfigStore {

    public SSLConfig() {
    }

    public SSLConfig(ConfigStorage storage) {
        super(storage);
    }

    public SSLConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getCipherPreferences() throws EBaseException {
        return getString("cipherpref", "");
    }

    public void setCipherPreferences(String cipherPrefs) throws EBaseException {
        putString("cipherpref", cipherPrefs);
    }

    public String getECType(String certType) throws EBaseException {
        return getString(certType + ".ectype", "ECDHE");
    }
}
