//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.connector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides <subsystem>.connector.<id>.* parameters.
 */
public class ConnectorConfig extends ConfigStore {

    public ConnectorConfig(ConfigStorage storage) {
        super(storage);
    }

    public ConnectorConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public boolean getEnable() throws EBaseException {
        return getBoolean("enable", true);
    }

    public String getClassName() throws EBaseException {
        return getString("class", null);
    }

    public boolean getLocal() throws EBaseException {
        return getBoolean("local");
    }

    public String getID() throws EBaseException {
        return getString("id");
    }

    public String getHost() throws EBaseException {
        return getString("host");
    }

    public int getPort() throws EBaseException {
        return getInteger("port");
    }

    public String getURI() throws EBaseException {
        return getString("uri");
    }

    public ConfigStore getURIs() {
        return getSubStore("uri");
    }

    public String getNickname() throws EBaseException {
        return getString("nickName", null);
    }

    public String getClientCiphers() throws EBaseException {
        return getString("clientCiphers", null);
    }

    public int getResendInterval() throws EBaseException {
        return getInteger("resendInterval", -1);
    }

    public int getTimeout() throws EBaseException {
        return getInteger("timeout", 0);
    }

    public int getMinHttpConns() throws EBaseException {
        return getInteger("minHttpConns", 1);
    }

    public int getMaxHttpConns() throws EBaseException {
        return getInteger("maxHttpConns", 15);
    }
}
