package com.netscape.cms.servlet.admin;
// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---


import org.dogtagpki.server.kra.KRAEngine;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * A class representing an administration servlet. This
 * servlet is responsible to serve Certificate Server
 * level administrative operations such as configuration
 * parameter updates.
 */
public class KRACMSAdminServlet extends CMSAdminServlet {

    public boolean isSubsystemInstalled(String subsystem) {
        return subsystem.equals("kra");
    }

    void readSubsystem(NameValuePairs params) {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);

        params.put(kra.getId(), Constants.PR_KRA_INSTANCE);
    }

    public void readEncryption(NameValuePairs params) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);
        String kraNickname = kra.getNickname();

        params.put(Constants.PR_CERT_TRANS, getCertNickname(kraNickname));
    }

    String getKRANickname() throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);

        return kra.getNickname();
    }

    void setKRANickname(String nickname) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);

        kra.setNickname(nickname);
    }

    String getKRANewnickname() throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);

        return kra.getNewNickName();
    }

    void setKRANewnickname(String tokenName, String nickname) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);

        if (CryptoUtil.isInternalToken(tokenName)) {
            kra.setNewNickName(nickname);

        } else if (tokenName.equals("") && nickname.equals("")) {
            kra.setNewNickName("");

        } else {
            kra.setNewNickName(tokenName + ":" + nickname);
        }
    }

    public void modifyKRACert(String nickname) throws EBaseException {

        KRAEngine engine = KRAEngine.getInstance();
        KeyRecoveryAuthority kra = (KeyRecoveryAuthority) engine.getSubsystem(KeyRecoveryAuthority.ID);

        kra.setNickname(nickname);
    }
}
