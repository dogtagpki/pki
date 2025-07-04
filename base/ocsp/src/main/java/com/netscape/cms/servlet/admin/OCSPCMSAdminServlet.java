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


import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

import org.dogtagpki.server.ocsp.OCSPEngine;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.security.SigningUnit;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.ocsp.OCSPAuthority;

/**
 * A class representing an administration servlet. This
 * servlet is responsible to serve Certificate Server
 * level administrative operations such as configuration
 * parameter updates.
 */
@WebServlet(
        name = "ocspserver",
        urlPatterns = "/server",
        initParams = {
                @WebInitParam(name="ID",       value="ocspserver"),
                @WebInitParam(name="AuthzMgr", value="BasicAclAuthz")
        }
)
public class OCSPCMSAdminServlet extends CMSAdminServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public boolean isSubsystemInstalled(String subsystem) {
        return subsystem.equals("ocsp");
    }

    @Override
    void readSubsystem(NameValuePairs params) {

        OCSPEngine engine = OCSPEngine.getInstance();
        OCSPAuthority ocsp = (OCSPAuthority) engine.getSubsystem(OCSPAuthority.ID);

        params.put(ocsp.getId(), Constants.PR_OCSP_INSTANCE);
    }

    @Override
    String getOCSPNickname() {

        OCSPEngine engine = OCSPEngine.getInstance();
        OCSPAuthority ocsp = (OCSPAuthority) engine.getSubsystem(OCSPAuthority.ID);
        SigningUnit signingUnit = ocsp.getSigningUnit();

        return signingUnit.getNickname();
    }

    @Override
    String getOCSPNewnickname() throws EBaseException {

        OCSPEngine engine = OCSPEngine.getInstance();
        OCSPAuthority ocsp = (OCSPAuthority) engine.getSubsystem(OCSPAuthority.ID);
        SigningUnit signingUnit = ocsp.getSigningUnit();

        return signingUnit.getNewNickName();
    }

    @Override
    void setOCSPNewnickname(String tokenName, String nickname) throws EBaseException {

        OCSPEngine engine = OCSPEngine.getInstance();
        OCSPAuthority ocsp = (OCSPAuthority) engine.getSubsystem(OCSPAuthority.ID);
        SigningUnit signingUnit = ocsp.getSigningUnit();

        if (CryptoUtil.isInternalToken(tokenName)) {
            signingUnit.setNewNickName(nickname);

        } else if (tokenName.equals("") && nickname.equals("")) {
            signingUnit.setNewNickName("");

        } else {
            signingUnit.setNewNickName(tokenName + ":" + nickname);
        }
    }

    @Override
    public void installOCSPSigningCert(
            String fullName,
            String nickname,
            String tokenName
            ) throws EBaseException {

        OCSPEngine engine = OCSPEngine.getInstance();
        OCSPAuthority ocsp = (OCSPAuthority) engine.getSubsystem(OCSPAuthority.ID);

        setOCSPNewnickname("", "");

        SigningUnit signingUnit = ocsp.getSigningUnit();

        if (fullName.equals(nickname)) {
            signingUnit.updateConfig(fullName, CryptoUtil.INTERNAL_TOKEN_NAME);
        } else {
            signingUnit.updateConfig(fullName, tokenName);
        }
    }
}
