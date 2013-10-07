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
package com.netscape.cms.servlet.cert;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import netscape.security.extensions.CertInfo;
import netscape.security.x509.CertificateSerialNumber;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;

/**
 * Certificate Renewal
 *
 * @version $Revision$, $Date$
 */
public class RenewalServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = -3094124661102395244L;

    // renewal templates.
    public static final String RENEWAL_SUCCESS_TEMPLATE = "RenewalSuccess.template";

    // http params
    public static final String CERT_TYPE = "certType";
    public static final String SERIAL_NO = "serialNo";
    // XXX can't do pkcs10 cause it's got no serial no.
    // (unless put serial no in pki attributes)
    // public static final String PKCS10 = "pkcs10";
    public static final String IMPORT_CERT = "importCert";

    private String mRenewalSuccessTemplate = RENEWAL_SUCCESS_TEMPLATE;
    private ICMSTemplateFiller mRenewalSuccessFiller = new ImportCertsTemplateFiller();

    public RenewalServlet() {
        super();
    }

    /**
     * initialize the servlet. This servlet makes use of the
     * template file "RenewalSuccess.template" to render the
     * response
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success template. has same info as enrollment.
        mTemplates.remove(ICMSRequest.SUCCESS);
        try {
            mRenewalSuccessTemplate = sc.getInitParameter(
                        PROP_SUCCESS_TEMPLATE);
            if (mRenewalSuccessTemplate == null)
                mRenewalSuccessTemplate = RENEWAL_SUCCESS_TEMPLATE;
            String fillername =
                    sc.getInitParameter(PROP_SUCCESS_TEMPLATE_FILLER);

            if (fillername != null) {
                ICMSTemplateFiller filler = newFillerObject(fillername);

                if (filler != null)
                    mRenewalSuccessFiller = filler;
            }
        } catch (Exception e) {
            // this should never happen.
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_IMP_INIT_SERV_ERR", e.toString(),
                            mId));
        }

    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        long startTime = CMS.getCurrentDate().getTime();
        IArgBlock httpParams = cmsReq.getHttpParams();
        HttpServletRequest httpReq = cmsReq.getHttpReq();

        // renewal requires either:
        //  - coming from ee:
        //		- old cert from ssl client auth
        //		- old certs from auth manager
        // 	- coming from agent or trusted RA:
        //  	- serial no of cert to be renewed.

        BigInteger old_serial_no = null;
        X509CertImpl old_cert = null;
        X509CertImpl renewed_cert = null;
        Date notBefore = null;
        Date notAfter = null;
        boolean doSaveAuthToken = false;

        IAuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "renew");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        String authMgr = AuditFormat.NOAUTH;

        if (authToken != null && !mAuthMgr.equals("sslClientCertAuthMgr")) {
            authMgr =
                    authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
        }

        // coming from agent
        if (mAuthMgr != null && mAuthMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
            X509Certificate[] cert = new X509Certificate[1];

            old_serial_no = getCertFromAgent(httpParams, cert);
            old_cert = (X509CertImpl) cert[0];

            // optional validity params from input.
            int beginYear = httpParams.getValueAsInt("beginYear", -1);
            int beginMonth = httpParams.getValueAsInt("beginMonth", -1);
            int beginDate = httpParams.getValueAsInt("beginDate", -1);
            int endYear = httpParams.getValueAsInt("endYear", -1);
            int endMonth = httpParams.getValueAsInt("endMonth", -1);
            int endDate = httpParams.getValueAsInt("endDate", -1);

            if (beginYear != -1 && beginMonth != -1 && beginDate != -1 &&
                    endYear != -1 && endMonth != -1 && endDate != -1) {
                Calendar calendar = Calendar.getInstance();
                calendar.set(beginYear, beginMonth, beginDate);
                notBefore = calendar.getTime();
                calendar.set(endYear, endMonth, endDate);
                notAfter = calendar.getTime();
            }
        } // coming from client
        else {
            // from auth manager
            X509CertImpl[] cert = new X509CertImpl[1];

            old_serial_no = getCertFromAuthMgr(authToken, cert);
            old_cert = cert[0];
        }

        IRequest req = null;

        try {
            // get ready to send request to request queue.
            X509CertInfo new_certInfo = null;

            req = mRequestQueue.newRequest(IRequest.RENEWAL_REQUEST);
            req.setExtData(IRequest.OLD_SERIALS, new BigInteger[] { old_serial_no });
            if (old_cert != null) {
                req.setExtData(IRequest.OLD_CERTS,
                        new X509CertImpl[] { old_cert }
                        );
                // create new certinfo from old_cert contents.
                X509CertInfo old_certInfo = (X509CertInfo)
                        old_cert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

                new_certInfo = new X509CertInfo(old_certInfo.getEncodedInfo());
            } else {
                // if no old cert (came from RA agent) create new cert info
                // (serializable) to pass through policies. And set the old
                // serial number to pick up.
                new_certInfo = new CertInfo();
                new_certInfo.set(X509CertInfo.SERIAL_NUMBER,
                        new CertificateSerialNumber(old_serial_no));
            }

            if (notBefore == null || notAfter == null) {
                notBefore = new Date(0);
                notAfter = new Date(0);
            }
            new_certInfo.set(X509CertInfo.VALIDITY,
                    new CertificateValidity(notBefore, notAfter));
            req.setExtData(IRequest.CERT_INFO, new X509CertInfo[] { new_certInfo }
                    );
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_SETTING_RENEWAL_VALIDITY_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SETTING_RENEWAL_VALIDITY_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_SETTING_RENEWAL_VALIDITY_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SETTING_RENEWAL_VALIDITY_ERROR"));
        }

        saveHttpHeaders(httpReq, req);
        saveHttpParams(httpParams, req);
        if (doSaveAuthToken)
            saveAuthToken(authToken, req);
        cmsReq.setIRequest(req);

        // send request to request queue.
        mRequestQueue.processRequest(req);

        // for audit log
        String initiative = null;
        String agentID = null;

        if (mAuthMgr != null && mAuthMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
            agentID = authToken.getInString("userid");
            initiative = AuditFormat.FROMAGENT + " agentID: " + agentID;
        } else {
            // request is from eegateway, so fromUser.
            initiative = AuditFormat.FROMUSER;
        }

        // check resulting status
        RequestStatus status = req.getRequestStatus();

        if (status != RequestStatus.COMPLETE) {
            cmsReq.setIRequestStatus();
            // audit log the status
            if (status == RequestStatus.REJECTED) {
                Vector<String> messages = req.getExtDataInStringVector(IRequest.ERRORS);

                if (messages != null) {
                    Enumeration<String> msgs = messages.elements();
                    StringBuffer wholeMsg = new StringBuffer();

                    while (msgs.hasMoreElements()) {
                        wholeMsg.append("\n");
                        wholeMsg.append(msgs.nextElement());
                    }

                    mLogger.log(ILogger.EV_AUDIT,
                            ILogger.S_OTHER,
                            AuditFormat.LEVEL,
                            AuditFormat.RENEWALFORMAT,
                            new Object[] {
                                    req.getRequestId(),
                                    initiative,
                                    authMgr,
                                    status.toString(),
                                    old_cert.getSubjectDN(),
                                    old_cert.getSerialNumber().toString(16),
                                    "violation: " +
                                            wholeMsg.toString() }
                            // wholeMsg},
                            // ILogger.L_MULTILINE
                            );
                } else { // no policy violation, from agent
                    mLogger.log(ILogger.EV_AUDIT,
                            ILogger.S_OTHER,
                            AuditFormat.LEVEL,
                            AuditFormat.RENEWALFORMAT,
                            new Object[] {
                                    req.getRequestId(),
                                    initiative,
                                    authMgr,
                                    status.toString(),
                                    old_cert.getSubjectDN(),
                                    old_cert.getSerialNumber().toString(16),
                                    "" }
                            );
                }
            } else { // other imcomplete status
                mLogger.log(ILogger.EV_AUDIT,
                        ILogger.S_OTHER,
                        AuditFormat.LEVEL,
                        AuditFormat.RENEWALFORMAT,
                        new Object[] {
                                req.getRequestId(),
                                initiative,
                                authMgr,
                                status.toString(),
                                old_cert.getSubjectDN(),
                                old_cert.getSerialNumber().toString(16),
                                "" }
                        );
            }
            return;
        }

        // service error
        Integer result = req.getExtDataInInteger(IRequest.RESULT);

        CMS.debug(
                "RenewalServlet: Result for request " + req.getRequestId() + " is " + result);
        if (result.equals(IRequest.RES_ERROR)) {
            CMS.debug(
                    "RenewalServlet: Result for request " + req.getRequestId() + " is error.");

            cmsReq.setStatus(ICMSRequest.ERROR);
            cmsReq.setError(req.getExtDataInString(IRequest.ERROR));
            String[] svcErrors =
                    req.getExtDataInStringArray(IRequest.SVCERRORS);

            if (svcErrors != null && svcErrors.length > 0) {
                for (int i = 0; i < svcErrors.length; i++) {
                    String err = svcErrors[i];

                    if (err != null) {
                        //System.out.println(
                        //"revocation servlet: setting error description "+
                        //err.toString());
                        cmsReq.setErrorDescription(err);
                        mLogger.log(ILogger.EV_AUDIT,
                                ILogger.S_OTHER,
                                AuditFormat.LEVEL,
                                AuditFormat.RENEWALFORMAT,
                                new Object[] {
                                        req.getRequestId(),
                                        initiative,
                                        authMgr,
                                        "completed with error: " +
                                                err,
                                        old_cert.getSubjectDN(),
                                        old_cert.getSerialNumber().toString(16),
                                        "" }
                                );

                    }
                }
            }
            return;
        }

        // success.
        X509CertImpl[] certs = req.getExtDataInCertArray(IRequest.ISSUED_CERTS);

        renewed_cert = certs[0];
        respondSuccess(cmsReq, renewed_cert);
        long endTime = CMS.getCurrentDate().getTime();

        mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.RENEWALFORMAT,
                new Object[] {
                        req.getRequestId(),
                        initiative,
                        authMgr,
                        "completed",
                        old_cert.getSubjectDN(),
                        old_cert.getSerialNumber().toString(16),
                        "new serial number: 0x" +
                                renewed_cert.getSerialNumber().toString(16) + " time: " + (endTime - startTime) }
                );

        return;
    }

    private void respondSuccess(
            CMSRequest cmsReq, X509CertImpl renewed_cert)
            throws EBaseException {
        cmsReq.setResult(new X509CertImpl[] { renewed_cert }
                );
        cmsReq.setStatus(ICMSRequest.SUCCESS);

        // check if cert should be imported.
        // browser must have input type set to nav or cartman since
        // there's no other way to tell

        IArgBlock httpParams = cmsReq.getHttpParams();

        if (checkImportCertToNav(cmsReq.getHttpResp(),
                httpParams, renewed_cert)) {
            return;
        } else {
            try {
                renderTemplate(cmsReq,
                        mRenewalSuccessTemplate, mRenewalSuccessFiller);
            } catch (IOException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGE_ERROR_DISPLAY_TEMPLATE_1",
                                mRenewalSuccessTemplate, e.toString()));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
            }
        }
        return;
    }

    protected BigInteger getRenewedCert(ICertRecord certRec)
            throws EBaseException {
        BigInteger renewedCert = null;
        String serial = null;
        MetaInfo meta = certRec.getMetaInfo();

        if (meta == null) {
            log(ILogger.LL_INFO,
                    "no meta info in cert serial 0x" + certRec.getSerialNumber().toString(16));
            return null;
        }
        serial = (String) meta.get(ICertRecord.META_RENEWED_CERT);
        if (serial == null) {
            log(ILogger.LL_INFO,
                    "no renewed cert in cert 0x" + certRec.getSerialNumber().toString(16));
            return null;
        }
        renewedCert = new BigInteger(serial);
        log(ILogger.LL_INFO,
                "renewed cert serial 0x" + renewedCert.toString(16) + "found for 0x" +
                        certRec.getSerialNumber().toString(16));
        return renewedCert;
    }

    /**
     * get certs to renew from agent.
     */
    private BigInteger getCertFromAgent(
            IArgBlock httpParams, X509Certificate[] certContainer)
            throws EBaseException {
        BigInteger serialno = null;
        X509Certificate cert = null;

        // get serial no
        serialno = httpParams.getValueAsBigInteger(SERIAL_NO, null);
        if (serialno == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_MISSING_SERIALNO_FOR_RENEW"));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_MISSING_SERIALNO_FOR_RENEW"));
        }
        // get cert from db if we're cert authority.
        if (mAuthority instanceof ICertificateAuthority) {
            cert = getX509Certificate(serialno);
            if (cert == null) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_MISSING_SERIALNO_FOR_RENEW_1", serialno.toString(16)));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_INVALID_CERT_FOR_RENEWAL"));
            }
        }
        certContainer[0] = cert;
        return serialno;
    }

    /**
     * get cert to renew from auth manager
     */
    private BigInteger getCertFromAuthMgr(
            IAuthToken authToken, X509Certificate[] certContainer)
            throws EBaseException {
        X509CertImpl cert =
                authToken.getInCert(AuthToken.TOKEN_CERT);

        if (cert == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_MISSING_CERTS_RENEW_FROM_AUTHMGR"));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_MISSING_CERTS_RENEW_FROM_AUTHMGR"));
        }
        if (mAuthority instanceof ICertificateAuthority &&
                !isCertFromCA(cert)) {
            log(ILogger.LL_FAILURE, "certficate from auth manager for " +
                    " renewal is not from this ca.");
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_INVALID_CERT_FOR_RENEWAL"));
        }
        certContainer[0] = cert;
        BigInteger serialno = ((X509Certificate) cert).getSerialNumber();

        return serialno;
    }

}
