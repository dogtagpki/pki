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
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Process Certificate Requests
 *
 * @version $Revision$, $Date$
 */
public class PKIProcessor implements IPKIProcessor {

    public final static String ADMIN_ENROLL_SERVLET_ID = "caadminEnroll";
    public static final String SUBJECT_NAME = "subject";
    public static final String OLD_CERT_TYPE = "csrCertType";
    public static final String CERT_TYPE = "certType";
    public static final String PKCS10_REQUEST = "pkcs10Request";
    public static final String SUBJECT_KEYGEN_INFO = "subjectKeyGenInfo";

    protected ICMSRequest mRequest = null;

    protected HttpServletRequest httpReq = null;
    protected String mServletId = null;
    protected CMSServlet mServlet = null;

    protected ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();

    public PKIProcessor() {
    }

    public PKIProcessor(ICMSRequest cmsReq, CMSServlet servlet) {
        mRequest = cmsReq;

        mServlet = servlet;

        if (mServlet == null || mRequest == null) {
            return;
        }

        mServletId = servlet.getId();

    }

    public void process(ICMSRequest cmsReq)
            throws EBaseException {
    }

    protected void fillCertInfo(
            String protocolString, X509CertInfo certInfo,
            IAuthToken authToken, IArgBlock httpParams)
            throws EBaseException {
    }

    protected X509CertInfo[] fillCertInfoArray(
            String protocolString, IAuthToken authToken, IArgBlock httpParams, IRequest req)
            throws EBaseException {
        return null;
    }

    /**
     * fill subject name, validity, extensions from authoken if any,
     * overriding what was in pkcs10.
     * fill subject name, extensions from http input if not authenticated.
     * requests not authenticated will need to be approved by an agent.
     */
    public static void fillCertInfoFromAuthToken(
            X509CertInfo certInfo, IAuthToken authToken)
            throws EBaseException {
        // override subject, validity and extensions from auth token
        // CA determines algorithm, version and issuer.
        // take key from keygen, cmc, pkcs10 or crmf.

        CMS.debug("PKIProcessor: fillCertInfoFromAuthToken");
        // subject name.
        try {
            String subjectname =
                    authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT);

            if (subjectname != null) {
                CertificateSubjectName certSubject = new CertificateSubjectName(new X500Name(subjectname));

                certInfo.set(X509CertInfo.SUBJECT, certSubject);
                log(ILogger.LL_INFO,
                        "cert subject set to " + certSubject + " from authtoken");
            }
        } catch (CertificateException e) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1",
                            e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_SUBJECT_NAME_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME",
                            e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_SUBJECT_NAME_ERROR"));
        }

        // validity
        try {
            CertificateValidity validity = null;
            Date notBefore =
                    authToken.getInDate(AuthToken.TOKEN_CERT_NOTBEFORE);
            Date notAfter =
                    authToken.getInDate(AuthToken.TOKEN_CERT_NOTAFTER);

            if (notBefore != null && notAfter != null) {
                validity = new CertificateValidity(notBefore, notAfter);
                certInfo.set(X509CertInfo.VALIDITY, validity);
                log(ILogger.LL_INFO,
                        "cert validity set to " + validity + " from authtoken");
            }
        } catch (CertificateException e) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_ERROR_SET_VALIDITY_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_VALIDITY_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_ERROR_SET_VALIDITY_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_VALIDITY_ERROR"));
        }

        // extensions
        try {
            CertificateExtensions extensions =
                    authToken.getInCertExts(X509CertInfo.EXTENSIONS);

            if (extensions != null) {
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
                log(ILogger.LL_INFO, "cert extensions set from authtoken");
            }
        } catch (CertificateException e) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_ERROR_SET_EXTENSIONS_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_EXTENSIONS_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_ERROR_SET_EXTENSIONS_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_EXTENSIONS_ERROR"));
        }
    }

    /**
     * fill subject name, extension from form.
     * this is done for unauthenticated requests.
     * unauthenticated requests must be approved by agents so these will
     * all be seen by and agent.
     */
    public static void fillCertInfoFromForm(
            X509CertInfo certInfo, IArgBlock httpParams)
            throws EBaseException {

        CMS.debug("PKIProcessor: fillCertInfoFromForm");
        // subject name.
        try {
            String subject = httpParams.getValueAsString(PKIProcessor.SUBJECT_NAME, null);

            if (subject == null) {
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_MISSING_SUBJECT_FROM_FORM"));
            }

            X500Name x500name = new X500Name(subject);

            certInfo.set(
                    X509CertInfo.SUBJECT, new CertificateSubjectName(x500name));

            fillValidityFromForm(certInfo, httpParams);
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_SUBJECT_NAME_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_SUBJECT_NAME_ERROR"));
        } catch (IllegalArgumentException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1", e.toString()));
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_REQ_ILLEGAL_CHARACTERS"));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CONVERT_DN_TO_X500NAME_ERROR"));
        }

        // requested extensions.
        // let polcies form extensions from http input.
    }

    public static void fillValidityFromForm(
            X509CertInfo certInfo, IArgBlock httpParams)
            throws EBaseException {
        CMS.debug("PKIProcessor: fillValidityFromForm!");
        try {
            String notValidBeforeStr = httpParams.getValueAsString("notValidBefore", null);
            String notValidAfterStr = httpParams.getValueAsString("notValidAfter", null);

            if (notValidBeforeStr != null && notValidAfterStr != null) {
                long notValidBefore = 0;
                long notValidAfter = 0;

                try {
                    notValidBefore = Long.parseLong(notValidBeforeStr);
                } catch (NumberFormatException e) {
                }
                try {
                    notValidAfter = Long.parseLong(notValidAfterStr);
                } catch (NumberFormatException e) {
                }

                if (notValidBefore > 0 && notValidAfter > 0) {
                    CertificateValidity validity = null;
                    Date notBefore = new Date(notValidBefore);
                    Date notAfter = new Date(notValidAfter);

                    if (notBefore != null && notAfter != null) {
                        validity = new CertificateValidity(notBefore, notAfter);
                        certInfo.set(X509CertInfo.VALIDITY, validity);
                        log(ILogger.LL_INFO,
                                "cert validity set to " + validity + " from authtoken");
                    }
                }
            }
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_SUBJECT_NAME_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_SUBJECT_NAME_ERROR"));
        }
    }

    /**
     * log according to authority category.
     */
    public static void log(int event, int level, String msg) {
        CMS.getLogger().log(event, ILogger.S_OTHER, level,
                "PKIProcessor " + ": " + msg);
    }

    public static void log(int level, String msg) {
        CMS.getLogger().log(ILogger.EV_SYSTEM, ILogger.S_OTHER, level,
                "PKIProcessor " + ": " + msg);
    }

    /**
     * Signed Audit Log
     *
     * This method is inherited by all extended "CMSServlet"s,
     * and is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    protected void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }

    /**
     * Signed Audit Log Subject ID
     *
     * This method is inherited by all extended "CMSServlet"s,
     * and is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    protected String auditSubjectID() {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String)
                    auditContext.get(SessionContext.USER_ID);

            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }
}
