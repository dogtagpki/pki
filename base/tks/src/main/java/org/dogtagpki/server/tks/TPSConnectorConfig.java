//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tks;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.SimpleProperties;

public class TPSConnectorConfig extends EngineConfig {

    public TPSConnectorConfig(ConfigStorage storage) {
        super(storage);
    }

    public TPSConnectorConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getHost() throws EBaseException {
        return getString("host", "");
    }

    public void setHost(String host) {
        putString("host", host);
    }

    public String getPort() throws EBaseException {
        return getString("port", "");
    }

    public void setPort(String port) {
        putString("port", port);
    }

    public String getUserID() throws EBaseException {
        return getString("userid", "");
    }

    public void setUserID(String userID) {
        putString("userid", userID);
    }

    public String getNickname() throws EBaseException {
        return getString("nickname", "");
    }

    public void setNickname(String nickname) {
        putString("nickname", nickname);
    }
}
