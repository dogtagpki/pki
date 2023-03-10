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

public class JssSubsystemConfig extends ConfigStore {

    public JssSubsystemConfig() {
    }

    public JssSubsystemConfig(ConfigStorage storage) {
        super(storage);
    }

    public JssSubsystemConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean isEnabled() throws EBaseException {
        return getBoolean("enable", true);
    }

    public String getNSSDatabaseDir() throws EBaseException {
        return getString("configDir", null);
    }

    public String getObscureMethod() throws EBaseException {
        return getString("obscureMethod", "zeroes");
    }

    public boolean getCloseNSSDatabase() throws EBaseException {
        return getBoolean("closeDatabases", false);
    }

    public SecureRandomConfig getSecureRandomConfig() {
        return getSubStore("random", SecureRandomConfig.class);
    }

    public SSLConfig getSSLConfig() {
        return getSubStore("ssl", SSLConfig.class);
    }
}
