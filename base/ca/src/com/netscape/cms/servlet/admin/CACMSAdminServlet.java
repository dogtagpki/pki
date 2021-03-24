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
package com.netscape.cms.servlet.admin;

import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;

import org.dogtagpki.server.ca.CAEngine;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.security.SigningUnit;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * A class representing an administration servlet. This
 * servlet is responsible to serve Certificate Server
 * level administrative operations such as configuration
 * parameter updates.
 */
public class CACMSAdminServlet extends CMSAdminServlet {

    public boolean isSubsystemInstalled(String subsystem) {
        return subsystem.equals("ca");
    }

    public void readEncryption(NameValuePairs params) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getSigningUnit();

        String caTokenName = signingUnit.getTokenName();
        if (caTokenName.equals(jssSubsystem.getInternalTokenName())) {
            caTokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
        }

        String caNickName = signingUnit.getNickname();

        // params.add(Constants.PR_CERT_CA, caTokenName + "," + caNickName);
        params.put(Constants.PR_CERT_CA, getCertNickname(caNickName));
    }

    public void modifyCACert(HttpServletRequest request, String value) throws EBaseException {

        String auditSubjectID = auditSubjectID();

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getSigningUnit();

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        if (tokenizer.countTokens() != 2) {
            // store a message in the signed audit log file
            String auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(request));

            audit(auditMessage);

            throw new EBaseException(CMS.getLogMessage("BASE_INVALID_UI_INFO"));
        }

        String tokenName = (String) tokenizer.nextElement();
        String nickName = (String) tokenizer.nextElement();

        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        if (CryptoUtil.isInternalToken(tokenName)) {
            tokenName = jssSubsystem.getInternalTokenName();
        } else {
            nickName = tokenName + ":" + nickName;
        }

        boolean isCACert = jssSubsystem.isCACert(nickName);
        if (!isCACert) {
            // store a message in the signed audit log file
            String auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(request));

            audit(auditMessage);

            throw new EBaseException(CMS.getLogMessage("BASE_NOT_CA_CERT"));
        }

        signingUnit.updateConfig(nickName, tokenName);
    }

    public void modifyServerCert(String nickname) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        modifyCAGatewayCert(ca, nickname);
    }
}
