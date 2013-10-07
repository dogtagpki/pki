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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extension;
import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.authentication.HashAuthentication;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;

/**
 * performs face-to-face enrollment.
 *
 * @version $Revision$, $Date$
 */
public class HashEnrollServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = 5532936020515258333L;

    public final static String ADMIN_ENROLL_SERVLET_ID = "adminEnroll";

    // enrollment templates.
    public static final String ENROLL_SUCCESS_TEMPLATE = "/ra/HashEnrollSuccess.template";

    // http params
    public static final String OLD_CERT_TYPE = "csrCertType";
    public static final String CERT_TYPE = "certType";
    // same as in ConfigConstant.java
    public static final String REQUEST_FORMAT = "reqFormat";
    public static final String REQUEST_CONTENT = "requestContent";
    public static final String SUBJECT_KEYGEN_INFO = "subjectKeyGenInfo";
    public static final String CRMF_REQUEST = "CRMFRequest";
    public static final String SUBJECT_NAME = "subject";
    public static final String CRMF_REQID = "crmfReqId";
    public static final String CHALLENGE_PASSWORD = "challengePhrase";

    private static final String CERT_AUTH_DUAL = "dual";
    private static final String CERT_AUTH_ENCRYPTION = "encryption";
    private static final String CERT_AUTH_SINGLE = "single";
    private static final String CLIENT_ISSUER = "clientIssuer";
    public static final String TPL_ERROR_FILE = "/ra/GenErrorHashDirEnroll.template";

    private String mEnrollSuccessTemplate = null;
    private ICMSTemplateFiller mEnrollSuccessFiller = new ImportCertsTemplateFiller();

    ICertificateAuthority mCa = null;
    ICertificateRepository mRepository = null;

    public HashEnrollServlet() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success template to allow direct import of keygen certs.
        mTemplates.remove(ICMSRequest.SUCCESS);
        try {
            mEnrollSuccessTemplate = sc.getInitParameter(
                    CMSServlet.PROP_SUCCESS_TEMPLATE);
            if (mEnrollSuccessTemplate == null)
                mEnrollSuccessTemplate = ENROLL_SUCCESS_TEMPLATE;
            String fillername =
                    sc.getInitParameter(PROP_SUCCESS_TEMPLATE_FILLER);

            if (fillername != null) {
                ICMSTemplateFiller filler = newFillerObject(fillername);

                if (filler != null)
                    mEnrollSuccessFiller = filler;
            }

            // cfu
            mCa = (ICertificateAuthority) CMS.getSubsystem("ca");

            init_testbed_hack(mConfig);
        } catch (Exception e) {
            // this should never happen.
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_IMP_INIT_SERV_ERR", e.toString(), mId));
        }
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        IArgBlock httpParams = cmsReq.getHttpParams();
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        String certType = null;

        String reqHost = httpReq.getRemoteHost();

        String host = httpParams.getValueAsString("hostname", null);

        if (host == null || !host.equals(reqHost)) {
            printError(cmsReq, "0");
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        }

        IConfigStore configStore = CMS.getConfigStore();
        String val = configStore.getString("hashDirEnrollment.name");
        IAuthSubsystem authSS = (IAuthSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
        IAuthManager authMgr = authSS.get(val);
        HashAuthentication mgr = (HashAuthentication) authMgr;

        Date date = new Date();
        long currTime = date.getTime();
        long timeout = mgr.getTimeout(reqHost);
        long lastlogin = mgr.getLastLogin(reqHost);
        long diff = currTime - lastlogin;

        boolean enable = mgr.isEnable(reqHost);

        if (!enable) {
            printError(cmsReq, "0");
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        }
        if (lastlogin == 0)
            mgr.setLastLogin(reqHost, currTime);
        else if (diff > timeout) {
            mgr.disable(reqHost);
            printError(cmsReq, "2");
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        }

        mgr.setLastLogin(reqHost, currTime);

        // support Enterprise 3.5.1 server where CERT_TYPE=csrCertType
        // instead of certType
        certType = httpParams.getValueAsString(OLD_CERT_TYPE, null);
        if (certType == null) {
            certType = httpParams.getValueAsString(CERT_TYPE, "client");
        } else {
            ;
        }

        processX509(cmsReq);
    }

    private void printError(CMSRequest cmsReq, String errorCode)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();
        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        mTemplates.remove(ICMSRequest.SUCCESS);
        header.addStringValue("authority", "Registration Manager");
        header.addStringValue("errorCode", errorCode);
        String formPath = TPL_ERROR_FILE;

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(formPath, httpReq, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", formPath, e.toString()));
            cmsReq.setError(new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR")));
            cmsReq.setStatus(ICMSRequest.ERROR);
            return;
        }
        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM",
                            e.toString()));
            cmsReq.setError(new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR")));
            cmsReq.setStatus(ICMSRequest.ERROR);
        }
    }

    protected void processX509(CMSRequest cmsReq)
            throws EBaseException {
        IArgBlock httpParams = cmsReq.getHttpParams();
        HttpServletRequest httpReq = cmsReq.getHttpReq();

        // create enrollment request in request queue.
        IRequest req = mRequestQueue.newRequest(IRequest.ENROLLMENT_REQUEST);

        /*
         * === certAuth based enroll ===
         * "certAuthEnroll" is on.
         * "certauthEnrollType can be one of the three:
         *		 single - it's for single cert enrollment
         *		 dual - it's for dual certs enrollment
         *		 encryption - getting the encryption cert only via
         *                    authentication of the signing cert
         *                    (crmf or keyGenInfo)
         */
        boolean certAuthEnroll = false;

        String certAuthEnrollOn =
                httpParams.getValueAsString("certauthEnroll", null);

        if ((certAuthEnrollOn != null) && (certAuthEnrollOn.equals("on"))) {
            certAuthEnroll = true;
            CMS.debug("HashEnrollServlet: certAuthEnroll is on");
        }

        String certauthEnrollType = null;

        if (certAuthEnroll == true) {
            certauthEnrollType =
                    httpParams.getValueAsString("certauthEnrollType", null);
            if (certauthEnrollType != null) {
                if (certauthEnrollType.equals("dual")) {
                    CMS.debug("HashEnrollServlet: certauthEnrollType is dual");
                } else if (certauthEnrollType.equals("encryption")) {
                    CMS.debug("HashEnrollServlet: certauthEnrollType is encryption");
                } else if (certauthEnrollType.equals("single")) {
                    CMS.debug("HashEnrollServlet: certauthEnrollType is single");
                } else {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_INVALID_CERTAUTH_ENROLL_TYPE_1", certauthEnrollType));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_INVALID_CERTAUTH_ENROLL_TYPE"));
                }
            } else {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_MISSING_CERTAUTH_ENROLL_TYPE"));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_MISSING_CERTAUTH_ENROLL_TYPE"));
            }
        }

        String challengePassword = httpParams.getValueAsString("challengePassword", "");

        cmsReq.setIRequest(req);
        saveHttpHeaders(httpReq, req);
        saveHttpParams(httpParams, req);
        IAuthToken token = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, token,
                    mAuthzResourceName, "import");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        X509Certificate sslClientCert = null;
        // cert auth enroll
        String certBasedOldSubjectDN = null;
        BigInteger certBasedOldSerialNum = null;

        // check if request was authenticated, if so set authtoken & certInfo.
        // also if authenticated, take certInfo from authToken.
        X509CertInfo certInfo = null;

        if (certAuthEnroll == true) {
            sslClientCert = getSSLClientCertificate(httpReq);
            if (sslClientCert == null) {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_MISSING_SSL_CLIENT_CERT"));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_MISSING_SSL_CLIENT_CERT"));
            }

            certBasedOldSubjectDN = sslClientCert.getSubjectDN().toString();
            certBasedOldSerialNum = sslClientCert.getSerialNumber();
            try {
                certInfo = (X509CertInfo)
                        ((X509CertImpl) sslClientCert).get(
                                X509CertImpl.NAME + "." + X509CertImpl.INFO);
            } catch (CertificateParsingException ex) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_MISSING_CERTINFO_ENCRYPT_CERT"));
                throw new ECMSGWException(
                        CMS.getUserMessage(getLocale(httpReq), "CMS_GW_MISSING_CERTINFO"));
            }
        } else {
            certInfo = CMS.getDefaultX509CertInfo();
        }

        X509CertInfo[] certInfoArray = new X509CertInfo[] { certInfo };

        //AuthToken authToken = access.getAuthToken();
        IConfigStore configStore = CMS.getConfigStore();
        String val = configStore.getString("hashDirEnrollment.name");
        IAuthSubsystem authSS = (IAuthSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
        IAuthManager authMgr1 = authSS.get(val);
        HashAuthentication mgr = (HashAuthentication) authMgr1;
        String pageID = httpParams.getValueAsString("pageID", null);

        IAuthToken authToken = mgr.getAuthToken(pageID);

        String authMgr = AuditFormat.NOAUTH;

        if (authToken == null) {
            printError(cmsReq, "3");
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        } else {
            authMgr =
                    authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
            // don't store agent token in request.
            // agent currently used for bulk issuance.
            // if (!authMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
            log(ILogger.LL_INFO,
                    "Enrollment request was authenticated by " +
                            authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME));
            fillCertInfoFromAuthToken(certInfo, authToken);
            // save authtoken attrs to request directly (for policy use)
            saveAuthToken(authToken, req);
            // req.set(IRequest.AUTH_TOKEN, authToken);
            // }
        }

        // support Enterprise 3.5.1 server where CERT_TYPE=csrCertType
        // instead of certType
        String certType = httpParams.getValueAsString(OLD_CERT_TYPE, null);
        if (certType == null) {
            certType = httpParams.getValueAsString(CERT_TYPE, "client");
        } else {
            // some policies may rely on the fact that
            // CERT_TYPE is set. So for 3.5.1 or eariler
            // we need to set CERT_TYPE here.
            req.setExtData(IRequest.HTTP_PARAMS, CERT_TYPE, certType);
        }

        String crmf =
                httpParams.getValueAsString(CRMF_REQUEST, null);

        if (certAuthEnroll == true) {

            fillCertInfoFromAuthToken(certInfo, authToken);

            // for dual certs
            if (certauthEnrollType.equals(CERT_AUTH_DUAL)) {
                if (mCa == null) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_NOT_A_CA"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_NOT_A_CA"));
                }

                // first, make sure the client cert is indeed a
                //				signing only cert
                if ((CMS.isSigningCert(sslClientCert) == false) ||
                        ((CMS.isSigningCert(sslClientCert) == true) &&
                        (CMS.isEncryptionCert(sslClientCert) == true))) {
                    // either it's not a signing cert, or it's a dual cert
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_INVALID_CERT_TYPE"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_INVALID_CERT_TYPE"));
                }
                X509Key key = null;

                // for signing cert
                key = (X509Key) sslClientCert.getPublicKey();
                try {
                    certInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));
                } catch (CertificateException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_FAILED_SET_KEY_FROM_CERT_AUTH_ENROLL_1", e.toString()));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_SET_KEY_FROM_CERT_AUTH_ENROLL_FAILED", e.toString()));
                } catch (IOException e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_FAILED_SET_KEY_FROM_CERT_AUTH_ENROLL_1", e.toString()));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_SET_KEY_FROM_CERT_AUTH_ENROLL_FAILED", e.toString()));
                }

                String filter =
                        "(&(x509cert.subject="
                                + certBasedOldSubjectDN + ")(!(x509cert.serialNumber=" + certBasedOldSerialNum
                                + "))(certStatus=VALID))";
                ICertRecordList list =
                        mCa.getCertificateRepository().findCertRecordsInList(filter,
                                null, 10);
                int size = list.getSize();
                Enumeration<ICertRecord> en = list.getCertRecords(0, size - 1);
                boolean gotEncCert = false;

                if (!en.hasMoreElements()) {
                    // pairing encryption cert not found
                } else {
                    X509CertInfo encCertInfo = CMS.getDefaultX509CertInfo();
                    X509CertInfo[] cInfoArray = new X509CertInfo[] { certInfo,
                            encCertInfo };
                    int i = 1;

                    while (en.hasMoreElements()) {
                        ICertRecord record = en.nextElement();
                        X509CertImpl cert = record.getCertificate();

                        // if not encryption cert only, try next one
                        if ((CMS.isEncryptionCert(cert) == false) ||
                                ((CMS.isEncryptionCert(cert) == true) &&
                                (CMS.isSigningCert(cert) == true))) {
                            continue;
                        }

                        key = (X509Key) cert.getPublicKey();
                        try {
                            encCertInfo = (X509CertInfo)
                                    cert.get(
                                            X509CertImpl.NAME + "." + X509CertImpl.INFO);

                        } catch (CertificateParsingException ex) {
                            log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSGW_MISSING_CERTINFO_ENCRYPT_CERT"));
                            throw new ECMSGWException(
                                    CMS.getUserMessage(getLocale(httpReq), "CMS_GW_MISSING_CERTINFO"));
                        }

                        try {
                            encCertInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));
                        } catch (CertificateException e) {
                            log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSGW_FAILED_SET_KEY_FROM_CERT_AUTH_ENROLL_1", e.toString()));
                            throw new ECMSGWException(
                                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_CERT_AUTH_ENROLL_FAILED", e.toString()));
                        } catch (IOException e) {
                            log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSGW_FAILED_SET_KEY_FROM_CERT_AUTH_ENROLL_1", e.toString()));
                            throw new ECMSGWException(
                                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_CERT_AUTH_ENROLL_FAILED", e.toString()));
                        }
                        fillCertInfoFromAuthToken(encCertInfo, authToken);

                        cInfoArray[i++] = encCertInfo;
                        certInfoArray = cInfoArray;
                        gotEncCert = true;
                        break;
                    }
                }

                if (gotEncCert == false) {
                    // encryption cert not found, bail
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_ENCRYPTION_CERT_NOT_FOUND"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_ENCRYPTION_CERT_NOT_FOUND"));
                }
            } else if (certauthEnrollType.equals(CERT_AUTH_ENCRYPTION)) {
                // first, make sure the client cert is indeed a
                //				signing only cert
                if ((CMS.isSigningCert(sslClientCert) == false) ||
                        ((CMS.isSigningCert(sslClientCert) == true) &&
                        (CMS.isEncryptionCert(sslClientCert) == true))) {
                    // either it's not a signing cert, or it's a dual cert
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_INVALID_CERT_TYPE"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_INVALID_CERT_TYPE"));
                }

                /*
                 * crmf
                 */
                if (crmf != null && crmf != "") {
                    certInfoArray = fillCRMF(crmf, authToken, httpParams, req);
                    req.setExtData(CLIENT_ISSUER,
                            sslClientCert.getIssuerDN().toString());
                    CMS.debug(
                            "HashEnrollServlet: sslClientCert issuerDN = " + sslClientCert.getIssuerDN().toString());
                } else {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_MISSING_KEYGEN_INFO"));
                    throw new ECMSGWException(CMS.getUserMessage(getLocale(httpReq),
                            "CMS_GW_MISSING_KEYGEN_INFO"));
                }
            } else if (certauthEnrollType.equals(CERT_AUTH_SINGLE)) {
                // have to be buried here to handle the issuer

                if (crmf != null && crmf != "") {
                    certInfoArray = fillCRMF(crmf, authToken, httpParams, req);
                } else {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_MISSING_KEYGEN_INFO"));
                    throw new ECMSGWException(CMS.getUserMessage(getLocale(httpReq),
                            "CMS_GW_MISSING_KEYGEN_INFO"));
                }
                req.setExtData(CLIENT_ISSUER,
                        sslClientCert.getIssuerDN().toString());
            }
        } else if (crmf != null && crmf != "") {
            certInfoArray = fillCRMF(crmf, authToken, httpParams, req);
        } else {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_MISSING_KEYGEN_INFO"));
            throw new ECMSGWException(CMS.getUserMessage(getLocale(httpReq),
                    "CMS_GW_MISSING_KEYGEN_INFO"));
        }

        req.setExtData(IRequest.CERT_INFO, certInfoArray);

        if (challengePassword != null && !challengePassword.equals("")) {
            String pwd = hashPassword(challengePassword);

            req.setExtData(CHALLENGE_PASSWORD, pwd);
        }

        // send request to request queue.
        mRequestQueue.processRequest(req);
        // process result.

        // render OLD_CERT_TYPE's response differently, we
        // dont want any javascript in HTML, and need to
        // override the default render.
        if (httpParams.getValueAsString(OLD_CERT_TYPE, null) != null) {
            try {
                renderServerEnrollResult(cmsReq);
                cmsReq.setStatus(ICMSRequest.SUCCESS); // no default render
            } catch (IOException ex) {
                cmsReq.setStatus(ICMSRequest.ERROR);
            }
            return;
        }

        //for audit log
        String initiative = null;
        String agentID = null;

        if (!authMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
            // request is from eegateway, so fromUser.
            initiative = AuditFormat.FROMUSER;
        } else {
            agentID = authToken.getInString("userid");
            initiative = AuditFormat.FROMAGENT + " agentID: " + agentID;
        }

        // if service not complete return standard templates.
        RequestStatus status = req.getRequestStatus();

        if (status != RequestStatus.COMPLETE) {
            cmsReq.setIRequestStatus(); // set status acc. to IRequest status.
            // audit log the status
            try {
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
                                AuditFormat.ENROLLMENTFORMAT,
                                new Object[] {
                                        req.getRequestId(),
                                        initiative,
                                        authMgr,
                                        status.toString(),
                                        certInfo.get(X509CertInfo.SUBJECT),
                                        " violation: " +
                                                wholeMsg.toString() },
                                ILogger.L_MULTILINE
                                );
                    } else { // no policy violation, from agent
                        mLogger.log(ILogger.EV_AUDIT,
                                ILogger.S_OTHER,
                                AuditFormat.LEVEL,
                                AuditFormat.ENROLLMENTFORMAT,
                                new Object[] {
                                        req.getRequestId(),
                                        initiative,
                                        authMgr,
                                        status.toString(),
                                        certInfo.get(X509CertInfo.SUBJECT), "" }
                                );
                    }
                } else { // other imcomplete status
                    mLogger.log(ILogger.EV_AUDIT,
                            ILogger.S_OTHER,
                            AuditFormat.LEVEL,
                            AuditFormat.ENROLLMENTFORMAT,
                            new Object[] {
                                    req.getRequestId(),
                                    initiative,
                                    authMgr,
                                    status.toString(),
                                    certInfo.get(X509CertInfo.SUBJECT), "" }
                            );
                }
            } catch (IOException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_CANT_GET_CERT_SUBJ_AUDITING", e.toString()));
            } catch (CertificateException e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_CANT_GET_CERT_SUBJ_AUDITING", e.toString()));
            }
            return;
        }
        // if service error use standard error templates.
        Integer result = req.getExtDataInInteger(IRequest.RESULT);

        if (result.equals(IRequest.RES_ERROR)) {

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
                        // audit log the error
                        try {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.ENROLLMENTFORMAT,
                                    new Object[] {
                                            req.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "completed with error: " +
                                                    err,
                                            certInfo.get(X509CertInfo.SUBJECT), "" }
                                    );
                        } catch (IOException e) {
                            log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSGW_CANT_GET_CERT_SUBJ_AUDITING",
                                            e.toString()));
                        } catch (CertificateException e) {
                            log(ILogger.LL_FAILURE,
                                    CMS.getLogMessage("CMSGW_CANT_GET_CERT_SUBJ_AUDITING",
                                            e.toString()));
                        }
                    }
                }
            }
            return;
        }

        // service success
        cmsReq.setStatus(ICMSRequest.SUCCESS);
        X509CertImpl[] issuedCerts =
                req.getExtDataInCertArray(IRequest.ISSUED_CERTS);

        // audit log the success.
        mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.ENROLLMENTFORMAT,
                new Object[] {
                        req.getRequestId(),
                        initiative,
                        authMgr,
                        "completed",
                        issuedCerts[0].getSubjectDN(),
                        "cert issued serial number: 0x" +
                                issuedCerts[0].getSerialNumber().toString(16) }
                );

        // return cert as mime type binary if requested.
        if (checkImportCertToNav(
                cmsReq.getHttpResp(), httpParams, issuedCerts[0])) {
            cmsReq.setStatus(ICMSRequest.SUCCESS);
            return;
        }

        // use success template.
        try {
            cmsReq.setResult(issuedCerts);
            renderTemplate(cmsReq, mEnrollSuccessTemplate,
                    mEnrollSuccessFiller);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_TEMP_REND_ERR", mEnrollSuccessFiller.toString(), e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_RETURNING_RESULT_ERROR"));
        }
        return;
    }

    /**
     * fill subject name, validity, extensions from authoken if any,
     * overriding what was in pkcs10.
     * fill subject name, extensions from http input if not authenticated.
     * requests not authenticated will need to be approved by an agent.
     */
    protected void fillCertInfoFromAuthToken(
            X509CertInfo certInfo, IAuthToken authToken)
            throws EBaseException {
        // override subject, validity and extensions from auth token
        // CA determines algorithm, version and issuer.
        // take key from keygen, cmc, pkcs10 or crmf.

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
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_SUBJECT_NAME_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_WARN,
                    CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1",
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
                    CMS.getLogMessage("CMSGW_ERROR_SET_VALIDITY_1",
                            e.toString()));
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
                    CMS.getLogMessage("CMSGW_ERROR_SET_EXTENSIONS_1",
                            e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_EXTENSIONS_ERROR"));
        }
    }

    protected X509CertInfo[] fillCRMF(
            String crmf, IAuthToken authToken, IArgBlock httpParams, IRequest req)
            throws EBaseException {
        try {
            byte[] crmfBlob = CMS.AtoB(crmf);
            ByteArrayInputStream crmfBlobIn =
                    new ByteArrayInputStream(crmfBlob);

            SEQUENCE crmfMsgs = (SEQUENCE)
                    new SEQUENCE.OF_Template(new CertReqMsg.Template()).decode(crmfBlobIn);

            int nummsgs = crmfMsgs.size();
            X509CertInfo[] certInfoArray = new X509CertInfo[nummsgs];

            for (int i = 0; i < nummsgs; i++) {
                // decode message.
                CertReqMsg certReqMsg = (CertReqMsg) crmfMsgs.elementAt(i);

                /*
                 if (certReqMsg.hasPop()) {
                 try {
                 certReqMsg.verify();
                 } catch (ChallengeResponseException ex) {
                 // create and save the challenge
                 // construct the cmmf message together
                 // in a sequence to challenge the requestor
                 } catch (Exception e) {
                 // failed, should only affect one request
                 }
                 }
                 */
                CertRequest certReq = certReqMsg.getCertReq();
                INTEGER certReqId = certReq.getCertReqId();
                int srcId = certReqId.intValue();

                req.setExtData(IRequest.CRMF_REQID, String.valueOf(srcId));

                CertTemplate certTemplate = certReq.getCertTemplate();
                X509CertInfo certInfo = CMS.getDefaultX509CertInfo();

                // get key
                SubjectPublicKeyInfo spki = certTemplate.getPublicKey();
                ByteArrayOutputStream keyout = new ByteArrayOutputStream();

                spki.encode(keyout);
                byte[] keybytes = keyout.toByteArray();
                X509Key key = new X509Key();

                key.decode(keybytes);
                certInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));

                // field suggested notBefore and notAfter in CRMF
                // Tech Support #383184
                if (certTemplate.getNotBefore() != null || certTemplate.getNotAfter() != null) {
                    CertificateValidity certValidity =
                            new CertificateValidity(certTemplate.getNotBefore(), certTemplate.getNotAfter());

                    certInfo.set(X509CertInfo.VALIDITY, certValidity);
                }

                if (certTemplate.hasSubject()) {
                    Name subjectdn = certTemplate.getSubject();
                    ByteArrayOutputStream subjectEncStream =
                            new ByteArrayOutputStream();

                    subjectdn.encode(subjectEncStream);
                    byte[] subjectEnc = subjectEncStream.toByteArray();
                    X500Name subject = new X500Name(subjectEnc);

                    certInfo.set(X509CertInfo.SUBJECT,
                            new CertificateSubjectName(subject));
                } else if (authToken == null ||
                        authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT) == null) {
                    // No subject name - error!
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("CMSGW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                }

                // get extensions
                CertificateExtensions extensions = null;

                try {
                    extensions = (CertificateExtensions)
                            certInfo.get(X509CertInfo.EXTENSIONS);
                } catch (CertificateException e) {
                    extensions = null;
                } catch (IOException e) {
                    extensions = null;
                }
                if (certTemplate.hasExtensions()) {
                    // put each extension from CRMF into CertInfo.
                    // index by extension name, consistent with
                    // CertificateExtensions.parseExtension() method.
                    if (extensions == null)
                        extensions = new CertificateExtensions();
                    int numexts = certTemplate.numExtensions();

                    for (int j = 0; j < numexts; j++) {
                        org.mozilla.jss.pkix.cert.Extension jssext =
                                certTemplate.extensionAt(j);
                        boolean isCritical = jssext.getCritical();
                        org.mozilla.jss.asn1.OBJECT_IDENTIFIER jssoid =
                                jssext.getExtnId();
                        long[] numbers = jssoid.getNumbers();
                        int[] oidNumbers = new int[numbers.length];

                        for (int k = numbers.length - 1; k >= 0; k--) {
                            oidNumbers[k] = (int) numbers[k];
                        }
                        ObjectIdentifier oid =
                                new ObjectIdentifier(oidNumbers);
                        org.mozilla.jss.asn1.OCTET_STRING jssvalue =
                                jssext.getExtnValue();
                        ByteArrayOutputStream jssvalueout =
                                new ByteArrayOutputStream();

                        jssvalue.encode(jssvalueout);
                        byte[] extValue = jssvalueout.toByteArray();

                        Extension ext =
                                new Extension(oid, isCritical, extValue);

                        extensions.parseExtension(ext);
                    }

                    certInfo.set(X509CertInfo.VERSION,
                            new CertificateVersion(CertificateVersion.V3));
                    certInfo.set(X509CertInfo.EXTENSIONS, extensions);

                }

                // Added a new configuration parameter
                // eeGateway.Enrollment.authTokenOverride=[true|false]
                // By default, it is set to true. In most
                // of the case, administrator would want
                // to have the control of the subject name
                // formulation.
                // -- CRMFfillCert
                if (authToken != null &&
                        authToken.getInString(AuthToken.TOKEN_CERT_SUBJECT) != null) {
                    // if authenticated override subect name, validity and
                    // extensions if any from authtoken.
                    fillCertInfoFromAuthToken(certInfo, authToken);
                }

                certInfoArray[i] = certInfo;
            }

            do_testbed_hack(nummsgs, certInfoArray, httpParams);

            return certInfoArray;
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1",
                            e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        } catch (InvalidBERException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        } catch (InvalidKeyException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1",
                            e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"));
        }
    }

    protected void renderServerEnrollResult(CMSRequest cmsReq) throws
            IOException {
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        httpResp.setContentType("text/html");
        ServletOutputStream out = null;

        out = httpResp.getOutputStream();

        // get template based on request status
        out.println("<HTML>");
        out.println("<TITLE>");
        out.println("Server Enrollment");
        out.println("</TITLE>");
        // out.println("<BODY BGCOLOR=white>");

        if (cmsReq.getIRequest().getRequestStatus().equals(RequestStatus.COMPLETE)) {
            out.println("<H1>");
            out.println("SUCCESS");
            out.println("</H1>");
            out.println("Your request is submitted and approved. Please cut and paste the certificate into your server."); // XXX - localize the message
            out.println("<P>");
            out.println("Request Creation Time: ");
            out.println(cmsReq.getIRequest().getCreationTime().toString());
            out.println("<P>");
            out.println("Request Status: ");
            out.println(cmsReq.getStatus().toString());
            out.println("<P>");
            out.println("Request ID: ");
            out.println(cmsReq.getIRequest().getRequestId().toString());
            out.println("<P>");
            out.println("Certificate: ");
            out.println("<P>");
            out.println("<PRE>");
            X509CertImpl certs[] =
                    cmsReq.getIRequest().getExtDataInCertArray(IRequest.ISSUED_CERTS);

            out.println(CMS.getEncodedCert(certs[0]));
            out.println("</PRE>");
            out.println("<P>");
            out.println("<!HTTP_OUTPUT REQUEST_CREATION_TIME=" +
                    cmsReq.getIRequest().getCreationTime().toString() + ">");
            out.println("<!HTTP_OUTPUT REQUEST_STATUS=" +
                    cmsReq.getStatus().toString() + ">");
            out.println("<!HTTP_OUTPUT REQUEST_ID=" +
                    cmsReq.getIRequest().getRequestId().toString() + ">");
            out.println("<!HTTP_OUTPUT X509_CERTIFICATE=" +
                    CMS.getEncodedCert(certs[0]) + ">");
        } else if (cmsReq.getIRequest().getRequestStatus().equals(RequestStatus.PENDING)) {
            out.println("<H1>");
            out.println("PENDING");
            out.println("</H1>");
            out.println("Your request is submitted. You can check on the status of your request with an authorized agent or local administrator by referring to the request ID."); // XXX - localize the message
            out.println("<P>");
            out.println("Request Creation Time: ");
            out.println(cmsReq.getIRequest().getCreationTime().toString());
            out.println("<P>");
            out.println("Request Status: ");
            out.println(cmsReq.getStatus().toString());
            out.println("<P>");
            out.println("Request ID: ");
            out.println(cmsReq.getIRequest().getRequestId().toString());
            out.println("<P>");
            out.println("<!HTTP_OUTPUT REQUEST_CREATION_TIME=" +
                    cmsReq.getIRequest().getCreationTime().toString() + ">");
            out.println("<!HTTP_OUTPUT REQUEST_STATUS=" +
                    cmsReq.getStatus().toString() + ">");
            out.println("<!HTTP_OUTPUT REQUEST_ID=" +
                    cmsReq.getIRequest().getRequestId().toString() + ">");
        } else {
            out.println("<H1>");
            out.println("ERROR");
            out.println("</H1>");
            out.println("<!INFO>");
            out.println("Please consult your local administrator for assistance."); // XXX - localize the message
            out.println("<!/INFO>");
            out.println("<P>");
            out.println("Request Status: ");
            out.println(cmsReq.getStatus().toString());
            out.println("<P>");
            out.println("Error: ");
            out.println(cmsReq.getError()); // XXX - need to parse in Locale
            out.println("<P>");
            out.println("<!HTTP_OUTPUT REQUEST_STATUS=" +
                    cmsReq.getStatus().toString() + ">");
            out.println("<!HTTP_OUTPUT ERROR=" +
                    cmsReq.getError() + ">");
        }

        /**
         * // include all the input data
         * IArgBlock args = cmsReq.getHttpParams();
         * Enumeration ele = args.getElements();
         * while (ele.hasMoreElements()) {
         * String eleT = (String)ele.nextElement();
         * out.println("<!HTTP_INPUT " + eleT + "=" +
         * args.get(eleT) + ">");
         * }
         **/

        out.println("</HTML>");
    }

    // XXX ALERT !!
    // Remove the following and calls to them when we bundle a cartman
    // later than alpha1.
    // These are here to cover up problem in cartman where the
    // key usage extension always ends up being digital signature only
    // and for rsa-ex ends up having no bits set.

    private boolean mIsTestBed = false;

    private void init_testbed_hack(IConfigStore config)
            throws EBaseException {
        mIsTestBed = config.getBoolean("isTestBed", true);
    }

    private void do_testbed_hack(
            int nummsgs, X509CertInfo[] certinfo, IArgBlock httpParams)
            throws EBaseException {
        if (!mIsTestBed)
            return;

        // get around bug in cartman - bits are off by one byte.
        for (int i = 0; i < certinfo.length; i++) {
            try {
                X509CertInfo cert = certinfo[i];
                CertificateExtensions exts = (CertificateExtensions)
                        cert.get(CertificateExtensions.NAME);

                if (exts == null) {
                    // should not happen.
                    continue;
                }
                KeyUsageExtension ext = (KeyUsageExtension)
                        exts.get(KeyUsageExtension.NAME);

                if (ext == null)
                    // should not happen
                    continue;
                byte[] value = ext.getExtensionValue();

                if (value[0] == 0x03 && value[1] == 0x02 && value[2] == 0x07) {
                    byte[] newvalue = new byte[value.length + 1];

                    newvalue[0] = 0x03;
                    newvalue[1] = 0x03;
                    newvalue[2] = 0x07;
                    newvalue[3] = value[3];
                    // force encryption certs to have digitial signature
                    // set too so smime can find the cert for encryption.
                    if (value[3] == 0x20) {

                        /*
                         newvalue[3] = 0x3f;
                         newvalue[4] = (byte)0x80;
                         */
                        if (httpParams.getValueAsBoolean(
                                "dual-use-hack", true)) {
                            newvalue[3] = (byte) 0xE0; // same as rsa-dual-use.
                        }
                    }
                    newvalue[4] = 0;
                    KeyUsageExtension newext =
                            new KeyUsageExtension(Boolean.valueOf(true),
                                    newvalue);

                    exts.delete(KeyUsageExtension.NAME);
                    exts.set(KeyUsageExtension.NAME, newext);
                }
            } catch (IOException e) {
                // should never happen
                continue;
            } catch (CertificateException e) {
                // should never happen
                continue;
            }
        }

    }
}
