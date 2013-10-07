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

import netscape.security.pkcs.PKCS10;
import netscape.security.pkcs.PKCS10Attribute;
import netscape.security.pkcs.PKCS10Attributes;
import netscape.security.pkcs.PKCS9Attribute;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extensions;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * PKCS10Processor process Certificate Requests in
 * PKCS10 format, as defined here:
 * http://www.rsasecurity.com/rsalabs/pkcs/pkcs-10/index.html
 *
 * @version $Revision$, $Date$
 */
public class PKCS10Processor extends PKIProcessor {

    private PKCS10 mPkcs10 = null;

    private final String USE_INTERNAL_PKCS10 = "internal";

    public PKCS10Processor() {

        super();
    }

    public PKCS10Processor(ICMSRequest cmsReq, CMSServlet servlet) {
        super(cmsReq, servlet);

    }

    public void process(ICMSRequest cmsReq)
            throws EBaseException {
    }

    public void fillCertInfo(
            PKCS10 pkcs10, X509CertInfo certInfo,
            IAuthToken authToken, IArgBlock httpParams)
            throws EBaseException {

        mPkcs10 = pkcs10;

        fillCertInfo(USE_INTERNAL_PKCS10, certInfo, authToken, httpParams);

    }

    public void fillCertInfo(
            String protocolString, X509CertInfo certInfo,
            IAuthToken authToken, IArgBlock httpParams)
            throws EBaseException {

        PKCS10 p10 = null;

        CMS.debug("PKCS10Processor:fillCertInfo");

        if (protocolString == null) {
            p10 = getPKCS10(httpParams);
        } else if (protocolString.equals(USE_INTERNAL_PKCS10)) {
            p10 = mPkcs10;
        } else {
            CMS.debug("PKCS10Processor::fillCertInfo() - p10 is null!");
            throw new EBaseException("p10 is null");
        }

        if (mServlet == null) {
            EBaseException ex = new ECMSGWException("Servlet property of PKCS10Processor is null.");

            throw ex;

        }

        // fill key
        X509Key key = p10.getSubjectPublicKeyInfo();

        if (key == null) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_MISSING_KEY_IN_P10"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_MISSING_KEY_IN_P10"));
        }
        CertificateX509Key certKey = new CertificateX509Key(key);

        try {
            certInfo.set(X509CertInfo.KEY, certKey);
        } catch (CertificateException e) {
            EBaseException ex = new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_P10_FAILED", e.toString()));

            log(ILogger.LL_FAILURE, ex.toString());
            throw ex;
        } catch (IOException e) {
            EBaseException ex = new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_P10_FAILED", e.toString()));

            log(ILogger.LL_FAILURE, ex.toString());
            throw ex;
        }

        X500Name subject = p10.getSubjectName();

        if (subject != null) {
            try {
                certInfo.set(X509CertInfo.SUBJECT,
                        new CertificateSubjectName(subject));
                log(ILogger.LL_INFO,
                        "Setting subject name " + subject + " from p10.");
            } catch (CertificateException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_FAILED_SET_SUBJECT_FROM_P10", e.toString()));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_SET_SUBJECT_FROM_P10_FAILED", e.toString()));
            } catch (IOException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_FAILED_SET_SUBJECT_FROM_P10", e.toString()));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_SET_SUBJECT_FROM_P10_FAILED", e.toString()));
            } catch (Exception e) {
                // if anything bad happens in X500 name parsing,
                // this will catch it.
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_FAILED_SET_SUBJECT_FROM_P10", e.toString()));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_SET_SUBJECT_FROM_P10_FAILED", e.toString()));
            }
        } else if (authToken == null ||
                authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT) == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_MISSING_SUBJECT_IN_P10"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_MISSING_SUBJECT_IN_P10"));
        }

        // fill extensions from pkcs 10 attributes if any.
        // other pkcs10 attributes are not recognized.
        // ExtensionReq ::= SEQUENCE OF Extension
        // ExtensionReq {pkcs-9 14}.
        try {
            PKCS10Attributes p10Attrs = p10.getAttributes();

            if (p10Attrs != null) {
                PKCS10Attribute p10Attr = p10Attrs.getAttribute(CertificateExtensions.NAME);

                if (p10Attr != null && p10Attr.getAttributeId().equals(
                        PKCS9Attribute.EXTENSION_REQUEST_OID)) {
                    Extensions exts0 = (Extensions) p10Attr.getAttributeValue();
                    DerOutputStream extOut = new DerOutputStream();

                    exts0.encode(extOut);
                    byte[] extB = extOut.toByteArray();
                    DerInputStream extIn = new DerInputStream(extB);
                    CertificateExtensions exts = new CertificateExtensions(extIn);

                    if (exts != null) {
                        certInfo.set(X509CertInfo.EXTENSIONS, exts);
                    }
                }
            }
            CMS.debug(
                    "PKCS10Processor: Seted cert extensions from pkcs10. ");
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_FAILED_SET_EXTENSIONS_FROM_P10", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_P10_FAILED", e.toString()));

        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_FAILED_SET_EXTENSIONS_FROM_P10", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_P10_FAILED", e.toString()));
        } catch (Exception e) {
            // if anything bad happens in extensions parsing,
            // this will catch it.
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_FAILED_SET_EXTENSIONS_FROM_P10", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_P10_FAILED", e.toString()));
        }

        // override pkcs10 attributes with authtoken attributes
        // like subject name, validity and extensions if any.
        // adminEnroll is an exception
        String authMgr = mServlet.getAuthMgr();

        if (authToken != null &&
                authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT) != null &&
                !(authMgr.equals(IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID))) {
            fillCertInfoFromAuthToken(certInfo, authToken);
        }

        // SPECIAL CASE:
        // if it is adminEnroll servlet, get the validity
        // from the http parameters.
        if (mServletId.equals(PKIProcessor.ADMIN_ENROLL_SERVLET_ID)) {
            fillValidityFromForm(certInfo, httpParams);
        }

    }

    private PKCS10 getPKCS10(IArgBlock httpParams)
            throws EBaseException {

        PKCS10 pkcs10 = null;

        String certType = null;

        // support Enterprise 3.5.1 server where CERT_TYPE=csrCertType
        // instead of certType
        certType = httpParams.getValueAsString(PKIProcessor.OLD_CERT_TYPE, null);
        if (certType == null) {
            certType = httpParams.getValueAsString(PKIProcessor.CERT_TYPE, "client");
        } else {
            // some policies may rely on the fact that
            // CERT_TYPE is set. So for 3.5.1 or eariler
            // we need to set CERT_TYPE  but not here.
        }
        if (certType.equals("client")) {
            // coming from MSIE
            String p10b64 = httpParams.getValueAsString(PKIProcessor.PKCS10_REQUEST, null);

            if (p10b64 != null) {
                try {
                    byte[] bytes = CMS.AtoB(p10b64);

                    pkcs10 = new PKCS10(bytes);
                } catch (Exception e) {
                    // ok, if the above fails, it could
                    // be a PKCS10 with header
                    pkcs10 = httpParams.getValueAsPKCS10(PKIProcessor.PKCS10_REQUEST, false, null);
                    // e.printStackTrace();
                }
            }

            //pkcs10 = httpParams.getValuePKCS10(PKCS10_REQUEST, null);

        } else {
            try {
                // coming from server cut & paste blob.
                pkcs10 = httpParams.getValueAsPKCS10(PKIProcessor.PKCS10_REQUEST, false, null);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        return pkcs10;

    }

}
