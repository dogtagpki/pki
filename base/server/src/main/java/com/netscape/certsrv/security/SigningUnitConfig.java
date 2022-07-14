//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.certsrv.security;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class SigningUnitConfig extends ConfigStore {

    public SigningUnitConfig(ConfigStorage storage) {
        super(storage);
    }

    public SigningUnitConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    public String getCertNickname() throws EBaseException {
        return getString("certnickname");
    }

    public void setCertNickname(String nickname) {
        putString("certnickname", nickname);
    }

    /**
     * @deprecated The cacertnickname has been replaced with certnickname.
     *
     * TODO: Remove cacertnickname property from existing instances with
     * an upgrade script.
     */
    @Deprecated(since = "11.3.0", forRemoval = true)
    public String getCACertNickname() throws EBaseException {
        return getString("cacertnickname");
    }

    /**
     * @deprecated The cacertnickname has been replaced with certnickname.
     *
     * TODO: Remove cacertnickname property from existing instances with
     * an upgrade script.
     */
    @Deprecated(since = "11.3.0", forRemoval = true)
    public void setCACertNickname(String nickname) {
        putString("cacertnickname", nickname);
    }

    public String getNewNickname() throws EBaseException {
        return getString("newNickname", "");
    }

    public void setNewNickname(String nickname) {
        putString("newNickname", nickname);
    }

    public String getTokenName() throws EBaseException {
        return getString("tokenname");
    }

    public void setTokenName(String tokenName) {
        putString("tokenname", tokenName);
    }

    public String getFullName() throws EBaseException {

        String nickname;
        try {
            nickname = getCertNickname();
        } catch (EPropertyNotFound e) {
            nickname = getCACertNickname();
        }

        String tokenName = getTokenName();

        String fullName;
        if (CryptoUtil.isInternalToken(tokenName)) {
            fullName = nickname;
        } else {
            fullName = tokenName + ":" + nickname;
        }

        return fullName;
    }

    public boolean getTestSignatureFailure() throws EBaseException {
        return getBoolean("testSignatureFailure", false);
    }

    public String getDefaultSigningAlgorithm() throws EBaseException {
        return getString("defaultSigningAlgorithm");
    }

    public void setDefaultSigningAlgorithm(String algorithm) {
        putString("defaultSigningAlgorithm", algorithm);
    }
}
