//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.servlet.cert.scep;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.SimpleProperties;

/**
 * Provides ca.scep.* parameters.
 */
public class SCEPConfig extends ConfigStore {

    public SCEPConfig(ConfigStorage storage) {
        super(storage);
    }

    public SCEPConfig(String name, SimpleProperties source) {
        super(name, source);
    }

    /**
     * Returns ca.scep.enable parameter.
     */
    public boolean getEnable() throws EBaseException {
        return getBoolean("enable", false);
    }

    /**
     * Returns ca.scep.hashAlgorithm parameter.
     */
    public String getHashAlgorithm() throws EBaseException {
        return getString("hashAlgorithm", "SHA256");
    }

    /**
     * Returns ca.scep.encryptionAlgorithm parameter.
     */
    public String getEncryptionAlgorithm() throws EBaseException {
        return getString("encryptionAlgorithm", "DES3");
    }

    /**
     * Returns ca.scep.nonceSizeLimit parameter.
     */
    public int getNonceSizeLimit() throws EBaseException {
        return getInteger("nonceSizeLimit", 0);
    }

    /**
     * Returns ca.scep.allowedHashAlgorithms parameter.
     */
    public String getAllowedHashAlgorithms() throws EBaseException {
        return getString("allowedHashAlgorithms", "SHA256,SHA512");
    }

    /**
     * Returns ca.scep.allowedEncryptionAlgorithms parameter.
     */
    public String getAllowedEncryptionAlgorithms() throws EBaseException {
        return getString("allowedEncryptionAlgorithms", "DES3");
    }

    /**
     * Returns ca.scep.allowedDynamicProfileIds parameter.
     */
    public String getAllowedDynamicProfileIds() throws EBaseException {
        return getString("allowedDynamicProfileIds", "caRouterCert");
    }

    /**
     * Returns ca.scep.nickname parameter.
     */
    public String getNickname(String defaultNickname) throws EBaseException {
        return getString("nickname", defaultNickname);
    }

    /**
     * Returns ca.scep.tokenname parameter.
     */
    public String getTokenName() throws EBaseException {
        return getString("tokenname", "");
    }
}
