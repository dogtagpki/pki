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
import java.util.Iterator;
import java.util.Locale;
import java.util.Vector;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.extensions.CertInfo;
import org.mozilla.jss.netscape.security.util.ObjectIdentifier;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.CertificateVersion;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.KeyUsageExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.authentication.HashAuthentication;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CAServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.RecordPagedList;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;

/**
 * performs face-to-face enrollment.
 *
 * @version $Revision$, $Date$
 */
public class HashEnrollServlet extends CAServlet {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(HashEnrollServlet.class);

    private static final long serialVersionUID = 5532936020515258333L;

    public static final String ADMIN_ENROLL_SERVLET_ID = "adminEnroll";

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

    CertificateAuthority mCa;

    public HashEnrollServlet() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success template to allow direct import of keygen certs.
        mTemplates.remove(CMSRequest.SUCCESS);
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
            CAEngine engine = CAEngine.getInstance();
            mCa = engine.getCA();

            initTestbedHack(mConfig);
        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("CMSGW_IMP_INIT_SERV_ERR", e.toString(), mId));
        }
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        ArgBlock httpParams = cmsReq.getHttpParams();
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        String certType = null;

        String reqHost = httpReq.getRemoteHost();

        String host = httpParams.getValueAsString("hostname", null);

        if (host == null || !host.equals(reqHost)) {
            printError(cmsReq, "0");
            cmsReq.setStatus(CMSRequest.SUCCESS);
            return;
        }

        CAEngine engine = CAEngine.getInstance();
        CAEngineConfig configStore = engine.getConfig();

        String val = configStore.getString("hashDirEnrollment.name");
        AuthSubsystem authSS = engine.getAuthSubsystem();
        AuthManager authMgr = authSS.get(val);
        HashAuthentication mgr = (HashAuthentication) authMgr;

        Date date = new Date();
        long currTime = date.getTime();
        long timeout = mgr.getTimeout(reqHost);
        long lastlogin = mgr.getLastLogin(reqHost);
        long diff = currTime - lastlogin;

        boolean enable = mgr.isEnable(reqHost);

        if (!enable) {
            printError(cmsReq, "0");
            cmsReq.setStatus(CMSRequest.SUCCESS);
            return;
        }
        if (lastlogin == 0)
            mgr.setLastLogin(reqHost, currTime);
        else if (diff > timeout) {
            mgr.disable(reqHost);
            printError(cmsReq, "2");
            cmsReq.setStatus(CMSRequest.SUCCESS);
            return;
        }

        mgr.setLastLogin(reqHost, currTime);

        // support Enterprise 3.5.1 server where CERT_TYPE=csrCertType
        // instead of certType
        certType = httpParams.getValueAsString(OLD_CERT_TYPE, null);
        if (certType == null) {
            certType = httpParams.getValueAsString(CERT_TYPE, "client");
        }

        processX509(cmsReq);
    }

    private void printError(CMSRequest cmsReq, String errorCode)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();
        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        mTemplates.remove(CMSRequest.SUCCESS);
        header.addStringValue("authority", "Registration Manager");
        header.addStringValue("errorCode", errorCode);
        String formPath = TPL_ERROR_FILE;

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(formPath, httpReq, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", formPath, e.toString()), e);
            cmsReq.setError(new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR")));
            cmsReq.setStatus(CMSRequest.ERROR);
            return;
        }
        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(CMSRequest.SUCCESS);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", e.toString()), e);
            cmsReq.setError(new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR")));
            cmsReq.setStatus(CMSRequest.ERROR);
        }
    }

    protected void processX509(CMSRequest cmsReq)
            throws EBaseException {
        ArgBlock httpParams = cmsReq.getHttpParams();
        HttpServletRequest httpReq = cmsReq.getHttpReq();

        // create enrollment request in request repository
        CAEngine engine = CAEngine.getInstance();
        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        Request req = requestRepository.createRequest(Request.ENROLLMENT_REQUEST);

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
            logger.debug("HashEnrollServlet: certAuthEnroll is on");
        }

        String certauthEnrollType = null;

        if (certAuthEnroll) {
            certauthEnrollType =
                    httpParams.getValueAsString("certauthEnrollType", null);
            if (certauthEnrollType != null) {
                if (certauthEnrollType.equals(CERT_AUTH_DUAL)) {
                    logger.debug("HashEnrollServlet: certauthEnrollType is dual");
                } else if (certauthEnrollType.equals(CERT_AUTH_ENCRYPTION)) {
                    logger.debug("HashEnrollServlet: certauthEnrollType is encryption");
                } else if (certauthEnrollType.equals(CERT_AUTH_SINGLE)) {
                    logger.debug("HashEnrollServlet: certauthEnrollType is single");
                } else {
                    logger.error(CMS.getLogMessage("CMSGW_INVALID_CERTAUTH_ENROLL_TYPE_1", certauthEnrollType));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_INVALID_CERTAUTH_ENROLL_TYPE"));
                }
            } else {
                logger.error(CMS.getLogMessage("CMSGW_MISSING_CERTAUTH_ENROLL_TYPE"));
                throw new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_MISSING_CERTAUTH_ENROLL_TYPE"));
            }
        }

        String challengePassword = httpParams.getValueAsString("challengePassword", "");

        cmsReq.setRequest(req);
        saveHttpHeaders(httpReq, req);
        saveHttpParams(httpParams, req);

        CAEngineConfig configStore = engine.getConfig();
        CertificateRepository cr = engine.getCertificateRepository();

        AuthToken token = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, token,
                    mAuthzResourceName, "import");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        X509Certificate sslClientCert = null;
        // cert auth enroll
        String certBasedOldSubjectDN = null;
        BigInteger certBasedOldSerialNum = null;

        // check if request was authenticated, if so set authtoken & certInfo.
        // also if authenticated, take certInfo from authToken.
        X509CertInfo certInfo = null;

        if (certAuthEnroll) {
            sslClientCert = getSSLClientCertificate(httpReq);
            if (sslClientCert == null) {
                logger.error(CMS.getLogMessage("CMSGW_MISSING_SSL_CLIENT_CERT"));
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
                logger.error(CMS.getLogMessage("CMSGW_MISSING_CERTINFO_ENCRYPT_CERT"), ex);
                throw new ECMSGWException(
                        CMS.getUserMessage(getLocale(httpReq), "CMS_GW_MISSING_CERTINFO"));
            }
        } else {
            certInfo = new CertInfo();
        }

        X509CertInfo[] certInfoArray = new X509CertInfo[] { certInfo };

        //AuthToken authToken = access.getAuthToken();
        String val = configStore.getString("hashDirEnrollment.name");
        AuthSubsystem authSS = engine.getAuthSubsystem();
        AuthManager authMgr1 = authSS.get(val);
        HashAuthentication mgr = (HashAuthentication) authMgr1;
        String pageID = httpParams.getValueAsString("pageID", null);

        AuthToken authToken = mgr.getAuthToken(pageID);

        String authMgr = AuditFormat.NOAUTH;

        if (authToken == null) {
            printError(cmsReq, "3");
            cmsReq.setStatus(CMSRequest.SUCCESS);
            return;
        }
        authMgr =
                authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
        // don't store agent token in request.
        // agent currently used for bulk issuance.
        // if (!authMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
        logger.info("Enrollment request was authenticated by {}",
                        authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME));
        fillCertInfoFromAuthToken(certInfo, authToken);
        // save authtoken attrs to request directly (for policy use)
        saveAuthToken(authToken, req);
        // req.set(Request.AUTH_TOKEN, authToken);
        // }

        // support Enterprise 3.5.1 server where CERT_TYPE=csrCertType
        // instead of certType
        String certType = httpParams.getValueAsString(OLD_CERT_TYPE, null);
        if (certType == null) {
            certType = httpParams.getValueAsString(CERT_TYPE, "client");
        } else {
            // some policies may rely on the fact that
            // CERT_TYPE is set. So for 3.5.1 or eariler
            // we need to set CERT_TYPE here.
            req.setExtData(Request.HTTP_PARAMS, CERT_TYPE, certType);
        }

        String crmf =
                httpParams.getValueAsString(CRMF_REQUEST, null);

        if (certAuthEnroll) {

            fillCertInfoFromAuthToken(certInfo, authToken);

            // for dual certs
            if (certauthEnrollType.equals(CERT_AUTH_DUAL)) {
                if (mCa == null) {
                    logger.error(CMS.getLogMessage("CMSGW_NOT_A_CA"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_NOT_A_CA"));
                }

                // first, make sure the client cert is indeed a
                //				signing only cert
                if (!CertUtils.isSigningCert((X509CertImpl) sslClientCert) ||
                        CertUtils.isSigningCert((X509CertImpl) sslClientCert) &&
                        CertUtils.isEncryptionCert((X509CertImpl) sslClientCert)) {
                    // either it's not a signing cert, or it's a dual cert
                    logger.error(CMS.getLogMessage("CMSGW_INVALID_CERT_TYPE"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_INVALID_CERT_TYPE"));
                }
                X509Key key = null;

                // for signing cert
                key = (X509Key) sslClientCert.getPublicKey();
                try {
                    certInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));
                } catch (CertificateException | IOException e) {
                    logger.error(CMS.getLogMessage("CMSGW_FAILED_SET_KEY_FROM_CERT_AUTH_ENROLL_1", e.toString()), e);
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_SET_KEY_FROM_CERT_AUTH_ENROLL_FAILED", e.toString()), e);
                }

                String filter =
                        "(&(x509cert.subject="
                                + certBasedOldSubjectDN + ")(!(x509cert.serialNumber=" + certBasedOldSerialNum
                                + "))(certStatus=VALID))";
                RecordPagedList<CertRecord> records = cr.findPagedCertRecords(filter, null, null);
                Iterator<CertRecord> iRec = records.iterator();
                boolean gotEncCert = false;

                if (!iRec.hasNext()) {
                    // pairing encryption cert not found
                } else {
                    X509CertInfo encCertInfo = new CertInfo();
                    X509CertInfo[] cInfoArray = new X509CertInfo[] { certInfo,
                            encCertInfo };
                    int i = 1;

                    while (iRec.hasNext() && !gotEncCert) {
                        CertRecord rec = iRec.next();
                        X509CertImpl cert = rec.getCertificate();

                        // if not encryption cert only, try next one
                        if (!CertUtils.isEncryptionCert(cert) ||
                                CertUtils.isEncryptionCert(cert) &&
                                CertUtils.isSigningCert(cert)) {
                            continue;
                        }

                        key = (X509Key) cert.getPublicKey();
                        try {
                            encCertInfo = (X509CertInfo)
                                    cert.get(
                                            X509CertImpl.NAME + "." + X509CertImpl.INFO);

                        } catch (CertificateParsingException ex) {
                            logger.error(CMS.getLogMessage("CMSGW_MISSING_CERTINFO_ENCRYPT_CERT"), ex);
                            throw new ECMSGWException(
                                    CMS.getUserMessage(getLocale(httpReq), "CMS_GW_MISSING_CERTINFO"), ex);
                        }

                        try {
                            encCertInfo.set(X509CertInfo.KEY, new CertificateX509Key(key));
                        } catch (CertificateException | IOException e) {
                            logger.error(CMS.getLogMessage("CMSGW_FAILED_SET_KEY_FROM_CERT_AUTH_ENROLL_1", e.toString()), e);
                            throw new ECMSGWException(
                                    CMS.getUserMessage("CMS_GW_SET_KEY_FROM_CERT_AUTH_ENROLL_FAILED", e.toString()), e);
                        }
                        fillCertInfoFromAuthToken(encCertInfo, authToken);

                        cInfoArray[i++] = encCertInfo;
                        certInfoArray = cInfoArray;
                        gotEncCert = true;
                    }
                }

                if (!gotEncCert) {
                    // encryption cert not found, bail
                    logger.error(CMS.getLogMessage("CMSGW_ENCRYPTION_CERT_NOT_FOUND"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_ENCRYPTION_CERT_NOT_FOUND"));
                }
            } else if (certauthEnrollType.equals(CERT_AUTH_ENCRYPTION)) {
                // first, make sure the client cert is indeed a
                //				signing only cert
                if (!CertUtils.isSigningCert((X509CertImpl) sslClientCert) ||
                        CertUtils.isSigningCert((X509CertImpl) sslClientCert) &&
                        CertUtils.isEncryptionCert((X509CertImpl) sslClientCert)) {
                    // either it's not a signing cert, or it's a dual cert
                    logger.error(CMS.getLogMessage("CMSGW_INVALID_CERT_TYPE"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_INVALID_CERT_TYPE"));
                }

                /*
                 * crmf
                 */
                if (crmf != null && !crmf.isBlank()) {
                    certInfoArray = fillCRMF(crmf, authToken, httpParams, req);
                    req.setExtData(CLIENT_ISSUER,
                            sslClientCert.getIssuerDN().toString());
                    logger.debug("HashEnrollServlet: sslClientCert issuerDN = {}", sslClientCert.getIssuerDN());
                } else {
                    logger.error(CMS.getLogMessage("CMSGW_MISSING_KEYGEN_INFO"));
                    throw new ECMSGWException(CMS.getUserMessage(getLocale(httpReq),
                            "CMS_GW_MISSING_KEYGEN_INFO"));
                }
            } else if (certauthEnrollType.equals(CERT_AUTH_SINGLE)) {
                // have to be buried here to handle the issuer

                if (crmf != null && !crmf.isBlank()) {
                    certInfoArray = fillCRMF(crmf, authToken, httpParams, req);
                } else {
                    logger.error(CMS.getLogMessage("CMSGW_MISSING_KEYGEN_INFO"));
                    throw new ECMSGWException(CMS.getUserMessage(getLocale(httpReq),
                            "CMS_GW_MISSING_KEYGEN_INFO"));
                }

                req.setExtData(CLIENT_ISSUER,
                        sslClientCert.getIssuerDN().toString());
            }
        } else if (crmf != null && !crmf.isBlank()) {
            certInfoArray = fillCRMF(crmf, authToken, httpParams, req);
        } else {
            logger.error(CMS.getLogMessage("CMSGW_MISSING_KEYGEN_INFO"));
            throw new ECMSGWException(CMS.getUserMessage(getLocale(httpReq),
                    "CMS_GW_MISSING_KEYGEN_INFO"));
        }

        req.setExtData(Request.CERT_INFO, certInfoArray);

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
                cmsReq.setStatus(CMSRequest.SUCCESS); // no default render
            } catch (Exception ex) {
                cmsReq.setStatus(CMSRequest.ERROR);
            }
            return;
        }

        //for audit log
        String initiative = null;
        String agentID = null;

        if (!authMgr.equals(AuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
            // request is from eegateway, so fromUser.
            initiative = AuditFormat.FROMUSER;
        } else {
            agentID = authToken.getInString("userid");
            initiative = AuditFormat.FROMAGENT + " agentID: " + agentID;
        }

        // if service not complete return standard templates.
        RequestStatus status = req.getRequestStatus();

        if (status != RequestStatus.COMPLETE) {
            cmsReq.setIRequestStatus(); // set status acc. to Request status.
            // audit log the status
            try {
                if (status == RequestStatus.REJECTED) {
                    Vector<String> messages = req.getExtDataInStringVector(Request.ERRORS);

                    if (messages != null) {
                        Enumeration<String> msgs = messages.elements();
                        StringBuilder wholeMsg = new StringBuilder();

                        while (msgs.hasMoreElements()) {
                            wholeMsg.append("\n");
                            wholeMsg.append(msgs.nextElement());
                        }
                        logger.info(
                                AuditFormat.ENROLLMENTFORMAT,
                                req.getRequestId(),
                                initiative,
                                authMgr,
                                status,
                                certInfo.get(X509CertInfo.SUBJECT),
                                " violation: " + wholeMsg
                        );
                    } else { // no policy violation, from agent
                        logger.info(
                                AuditFormat.ENROLLMENTFORMAT,
                                req.getRequestId(),
                                initiative,
                                authMgr,
                                status,
                                certInfo.get(X509CertInfo.SUBJECT),
                                ""
                        );
                    }
                } else { // other incomplete status
                    logger.info(
                            AuditFormat.ENROLLMENTFORMAT,
                            req.getRequestId(),
                            initiative,
                            authMgr,
                            status,
                            certInfo.get(X509CertInfo.SUBJECT),
                            ""
                    );
                }

            } catch (IOException e) {
                logger.error(CMS.getLogMessage("CMSGW_CANT_GET_CERT_SUBJ_AUDITING", e.toString()), e);

            } catch (CertificateException e) {
                logger.warn(CMS.getLogMessage("CMSGW_CANT_GET_CERT_SUBJ_AUDITING", e.toString()), e);
            }

            return;
        }
        // if service error use standard error templates.
        Integer result = req.getExtDataInInteger(Request.RESULT);

        if (result.equals(Request.RES_ERROR)) {

            cmsReq.setStatus(CMSRequest.ERROR);
            cmsReq.setError(req.getExtDataInString(Request.ERROR));
            String[] svcErrors =
                    req.getExtDataInStringArray(Request.SVCERRORS);

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
                            logger.info(
                                    AuditFormat.ENROLLMENTFORMAT,
                                    req.getRequestId(),
                                    initiative,
                                    authMgr,
                                    "completed with error: " + err,
                                    certInfo.get(X509CertInfo.SUBJECT),
                                    ""
                            );

                        } catch (CertificateException | IOException e) {
                            logger.warn(CMS.getLogMessage("CMSGW_CANT_GET_CERT_SUBJ_AUDITING", e.toString()), e);
                        }
                    }
                }
            }
            return;
        }

        // service success
        cmsReq.setStatus(CMSRequest.SUCCESS);
        X509CertImpl[] issuedCerts =
                req.getExtDataInCertArray(Request.ISSUED_CERTS);

        // audit log the success.
        logger.info(
                AuditFormat.ENROLLMENTFORMAT,
                req.getRequestId(),
                initiative,
                authMgr,
                "completed",
                issuedCerts[0].getSubjectDN(),
                "cert issued serial number: 0x" +
                        issuedCerts[0].getSerialNumber().toString(16)
        );

        // return cert as mime type binary if requested.
        if (checkImportCertToNav(
                cmsReq.getHttpResp(), httpParams, issuedCerts[0])) {
            cmsReq.setStatus(CMSRequest.SUCCESS);
            return;
        }

        // use success template.
        try {
            cmsReq.setResult(issuedCerts);
            renderTemplate(cmsReq, mEnrollSuccessTemplate,
                    mEnrollSuccessFiller);
            cmsReq.setStatus(CMSRequest.SUCCESS);

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_TEMP_REND_ERR", mEnrollSuccessFiller.toString(), e.toString()), e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_RETURNING_RESULT_ERROR"), e);
        }
    }

    /**
     * fill subject name, validity, extensions from authoken if any,
     * overriding what was in pkcs10.
     * fill subject name, extensions from http input if not authenticated.
     * requests not authenticated will need to be approved by an agent.
     */
    protected void fillCertInfoFromAuthToken(
            X509CertInfo certInfo, AuthToken authToken)
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
                logger.info("cert subject set to {} from authtoken", certSubject);
            }

        } catch (CertificateException | IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERROR_SET_SUBJECT_NAME_1", e.toString()), e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_SUBJECT_NAME_ERROR"), e);
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
                logger.info("cert validity set to {} from authtoken", validity);
            }

        } catch (CertificateException | IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERROR_SET_VALIDITY_1", e.toString()), e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_VALIDITY_ERROR"), e);
        }

        // extensions
        try {
            CertificateExtensions extensions =
                    authToken.getInCertExts(X509CertInfo.EXTENSIONS);

            if (extensions != null) {
                certInfo.set(X509CertInfo.EXTENSIONS, extensions);
                logger.info("cert extensions set from authtoken");
            }

        } catch (CertificateException | IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERROR_SET_EXTENSIONS_1", e.toString()), e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_SET_EXTENSIONS_ERROR"), e);
        }
    }

    protected X509CertInfo[] fillCRMF(
            String crmf, AuthToken authToken, ArgBlock httpParams, Request req)
            throws EBaseException {
        try {
            byte[] crmfBlob = Utils.base64decode(crmf);
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

                req.setExtData(Request.CRMF_REQID, String.valueOf(srcId));

                CertTemplate certTemplate = certReq.getCertTemplate();
                X509CertInfo certInfo = new CertInfo();

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
                    logger.error(CMS.getLogMessage("CMSGW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                    throw new ECMSGWException(
                            CMS.getUserMessage("CMS_GW_MISSING_SUBJECT_NAME_FROM_AUTHTOKEN"));
                }

                // get extensions
                CertificateExtensions extensions = null;

                try {
                    extensions = (CertificateExtensions)
                            certInfo.get(X509CertInfo.EXTENSIONS);
                } catch (CertificateException | IOException e) {
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

            doTestbedHack(certInfoArray, httpParams);

            return certInfoArray;

        } catch (CertificateException | IOException | InvalidBERException | InvalidKeyException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERROR_CRMF_TO_CERTINFO_1", e.toString()), e);
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_CRMF_TO_CERTINFO_ERROR"), e);
        }
    }

    protected void renderServerEnrollResult(CMSRequest cmsReq) throws Exception {
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

        if (cmsReq.getRequest().getRequestStatus().equals(RequestStatus.COMPLETE)) {
            out.println("<H1>");
            out.println("SUCCESS");
            out.println("</H1>");
            out.println("Your request is submitted and approved. Please cut and paste the certificate into your server."); // XXX - localize the message
            out.println("<P>");
            out.println("Request Creation Time: ");
            out.println(cmsReq.getRequest().getCreationTime().toString());
            out.println("<P>");
            out.println("Request Status: ");
            out.println(cmsReq.getStatus().toString());
            out.println("<P>");
            out.println("Request ID: ");
            out.println(cmsReq.getRequest().getRequestId().toString());
            out.println("<P>");
            out.println("Certificate: ");
            out.println("<P>");
            out.println("<PRE>");
            X509CertImpl[] certs =
                    cmsReq.getRequest().getExtDataInCertArray(Request.ISSUED_CERTS);

            out.println(CertUtil.toPEM(certs[0]));
            out.println("</PRE>");
            out.println("<P>");
            out.println("<!HTTP_OUTPUT REQUEST_CREATION_TIME=" +
                    cmsReq.getRequest().getCreationTime().toString() + ">");
            out.println("<!HTTP_OUTPUT REQUEST_STATUS=" +
                    cmsReq.getStatus().toString() + ">");
            out.println("<!HTTP_OUTPUT REQUEST_ID=" +
                    cmsReq.getRequest().getRequestId().toString() + ">");
            out.println("<!HTTP_OUTPUT X509_CERTIFICATE=" +
                    CertUtil.toPEM(certs[0]) + ">");
        } else if (cmsReq.getRequest().getRequestStatus().equals(RequestStatus.PENDING)) {
            out.println("<H1>");
            out.println("PENDING");
            out.println("</H1>");
            out.println("Your request is submitted. You can check on the status of your request with an authorized agent or local administrator by referring to the request ID."); // XXX - localize the message
            out.println("<P>");
            out.println("Request Creation Time: ");
            out.println(cmsReq.getRequest().getCreationTime().toString());
            out.println("<P>");
            out.println("Request Status: ");
            out.println(cmsReq.getStatus().toString());
            out.println("<P>");
            out.println("Request ID: ");
            out.println(cmsReq.getRequest().getRequestId().toString());
            out.println("<P>");
            out.println("<!HTTP_OUTPUT REQUEST_CREATION_TIME=" +
                    cmsReq.getRequest().getCreationTime().toString() + ">");
            out.println("<!HTTP_OUTPUT REQUEST_STATUS=" +
                    cmsReq.getStatus().toString() + ">");
            out.println("<!HTTP_OUTPUT REQUEST_ID=" +
                    cmsReq.getRequest().getRequestId().toString() + ">");
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
         * ArgBlock args = cmsReq.getHttpParams();
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

    private void initTestbedHack(ConfigStore config) throws EBaseException {
        mIsTestBed = config.getBoolean("isTestBed", true);
    }

    private void doTestbedHack(X509CertInfo[] certinfo, ArgBlock httpParams) {
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
            } catch (IOException | CertificateException e) {
                // should never happen
            }
        }

    }
}
