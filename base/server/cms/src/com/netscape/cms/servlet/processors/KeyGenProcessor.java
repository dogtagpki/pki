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
package com.netscape.cms.servlet.processors;

import java.io.IOException;
import java.security.cert.CertificateException;

import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.KeyGenInfo;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * KeyGenProcess parses Certificate request matching the
 * KEYGEN tag format used by Netscape Communicator 4.x
 *
 * @version $Revision$, $Date$
 */
public class KeyGenProcessor extends PKIProcessor {

    public KeyGenProcessor() {
        super();
    }

    public KeyGenProcessor(ICMSRequest cmsReq, CMSServlet servlet) {
        super(cmsReq, servlet);

    }

    public void process(ICMSRequest cmsReq)
            throws EBaseException {
    }

    public void fillCertInfo(
            String protocolString, X509CertInfo certInfo,
            IAuthToken authToken, IArgBlock httpParams)
            throws EBaseException {

        CMS.debug("KeyGenProcessor: fillCertInfo");

        if (mServlet == null) {
            return;
        }

        KeyGenInfo keyGenInfo = httpParams.getValueAsKeyGenInfo(
                PKIProcessor.SUBJECT_KEYGEN_INFO, null);

        // fill key
        X509Key key = null;

        key = keyGenInfo.getSPKI();
        if (key == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_MISSING_KEY_IN_KEYGENINFO"));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_MISSING_KEY_IN_KEYGENINFO"));
        }
        try {
            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    "Could not set key into certInfo from keygen. Error " + e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_KEYGEN_FAILED", e.toString()));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_FAILED_SET_KEY_FROM_KEYGEN_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_KEYGEN_FAILED", e.toString()));
        }

        String authMgr = mServlet.getAuthMgr();

        // if not authenticated, fill subject name, validity & extensions
        // from authtoken.
        if (authToken == null) {
            fillCertInfoFromForm(certInfo, httpParams);
        } else {
            if (authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT) == null) {
                // allow special case for agent gateway in admin enroll
                // and bulk issuance.
                if (!authMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID) &&
                        !authMgr.equals(IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID)) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                }
                fillCertInfoFromForm(certInfo, httpParams);
            } else {
                fillCertInfoFromAuthToken(certInfo, authToken);
            }
        }
    }
}
