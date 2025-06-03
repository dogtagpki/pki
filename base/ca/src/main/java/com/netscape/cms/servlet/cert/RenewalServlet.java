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
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.extensions.CertInfo;
import org.mozilla.jss.netscape.security.x509.CertificateSerialNumber;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.common.CAServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;

/**
 * Certificate Renewal
 */
@WebServlet(
        name = "caRenewal",
        urlPatterns = "/renewal",
        initParams = {
                @WebInitParam(name="GetClientCert",   value="true"),
                @WebInitParam(name="successTemplate", value="/ca/RenewalSuccess.template"),
                @WebInitParam(name="AuthzMgr",        value="BasicAclAuthz"),
                @WebInitParam(name="authority",       value="ca"),
                @WebInitParam(name="interface",       value="ee"),
                @WebInitParam(name="ID",              value="caRenewal"),
                @WebInitParam(name="resourceID",      value="certServer.ee.certificate"),
                @WebInitParam(name="AuthMgr",         value="sslClientCertAuthMgr")
        }
)
public class RenewalServlet extends CAServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RenewalServlet.class);
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
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success template. has same info as enrollment.
        mTemplates.remove(CMSRequest.SUCCESS);
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
            logger.warn(CMS.getLogMessage("CMSGW_IMP_INIT_SERV_ERR", e.toString(), mId), e);
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
        long startTime = new Date().getTime();
        ArgBlock httpParams = cmsReq.getHttpParams();
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

        AuthToken authToken = authenticate(cmsReq);

        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "renew");
        } catch (EAuthzAccessDenied e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        } catch (Exception e) {
            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        String authMgr = AuditFormat.NOAUTH;

        if (authToken != null && !mAuthMgr.equals("sslClientCertAuthMgr")) {
            authMgr =
                    authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
        }

        // coming from agent
        if (mAuthMgr != null && mAuthMgr.equals(AuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
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

        Request req = null;

        try {
            // get ready to send request to request queue.
            X509CertInfo new_certInfo = null;

            CAEngine engine = CAEngine.getInstance();
            CertRequestRepository requestRepository = engine.getCertRequestRepository();
            req = requestRepository.createRequest(Request.RENEWAL_REQUEST);
            req.setExtData(Request.OLD_SERIALS, new BigInteger[] { old_serial_no });
            if (old_cert != null) {
                req.setExtData(Request.OLD_CERTS,
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

            logger.info("RenewalServlet: - not before: " + notBefore);
            logger.info("RenewalServlet: - not after: " + notAfter);

            new_certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(notBefore, notAfter));
            req.setExtData(Request.CERT_INFO, new X509CertInfo[] { new_certInfo }
                    );
        } catch (CertificateException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERROR_SETTING_RENEWAL_VALIDITY_1", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_SETTING_RENEWAL_VALIDITY_ERROR"), e);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERROR_SETTING_RENEWAL_VALIDITY_1", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_SETTING_RENEWAL_VALIDITY_ERROR"), e);
        }

        saveHttpHeaders(httpReq, req);
        saveHttpParams(httpParams, req);
        if (doSaveAuthToken)
            saveAuthToken(authToken, req);
        cmsReq.setRequest(req);

        // send request to request queue.
        mRequestQueue.processRequest(req);

        // for audit log
        String initiative = null;
        String agentID = null;

        if (mAuthMgr != null && mAuthMgr.equals(AuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
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
                Vector<String> messages = req.getExtDataInStringVector(Request.ERRORS);

                if (messages != null) {
                    Enumeration<String> msgs = messages.elements();
                    StringBuffer wholeMsg = new StringBuffer();

                    while (msgs.hasMoreElements()) {
                        wholeMsg.append("\n");
                        wholeMsg.append(msgs.nextElement());
                    }

                    logger.info(
                            AuditFormat.RENEWALFORMAT,
                            req.getRequestId(),
                            initiative,
                            authMgr,
                            status,
                            old_cert.getSubjectName(),
                            old_cert.getSerialNumber().toString(16),
                            "violation: " + wholeMsg
                    );
                } else { // no policy violation, from agent
                    logger.info(
                            AuditFormat.RENEWALFORMAT,
                            req.getRequestId(),
                            initiative,
                            authMgr,
                            status,
                            old_cert.getSubjectName(),
                            old_cert.getSerialNumber().toString(16),
                            ""
                    );
                }
            } else { // other incomplete status
                logger.info(
                        AuditFormat.RENEWALFORMAT,
                        req.getRequestId(),
                        initiative,
                        authMgr,
                        status,
                        old_cert.getSubjectName(),
                        old_cert.getSerialNumber().toString(16),
                        ""
                );
            }
            return;
        }

        // service error
        Integer result = req.getExtDataInInteger(Request.RESULT);

        logger.debug("RenewalServlet: Result for request " + req.getRequestId() + " is " + result);
        if (result.equals(Request.RES_ERROR)) {
            logger.debug("RenewalServlet: Result for request " + req.getRequestId() + " is error.");

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
                        logger.info(
                                AuditFormat.RENEWALFORMAT,
                                req.getRequestId(),
                                initiative,
                                authMgr,
                                "completed with error: " + err,
                                old_cert.getSubjectName(),
                                old_cert.getSerialNumber().toString(16),
                                ""
                        );

                    }
                }
            }
            return;
        }

        // success.
        X509CertImpl[] certs = req.getExtDataInCertArray(Request.ISSUED_CERTS);

        renewed_cert = certs[0];
        respondSuccess(cmsReq, renewed_cert);
        long endTime = new Date().getTime();

        logger.info(
                AuditFormat.RENEWALFORMAT,
                req.getRequestId(),
                initiative,
                authMgr,
                "completed",
                old_cert.getSubjectName(),
                old_cert.getSerialNumber().toString(16),
                "new serial number: 0x" +
                        renewed_cert.getSerialNumber().toString(16) + " time: " + (endTime - startTime)
        );

        return;
    }

    private void respondSuccess(
            CMSRequest cmsReq, X509CertImpl renewed_cert)
            throws EBaseException {
        cmsReq.setResult(new X509CertImpl[] { renewed_cert }
                );
        cmsReq.setStatus(CMSRequest.SUCCESS);

        // check if cert should be imported.
        // browser must have input type set to nav or cartman since
        // there's no other way to tell

        ArgBlock httpParams = cmsReq.getHttpParams();

        if (checkImportCertToNav(cmsReq.getHttpResp(),
                httpParams, renewed_cert)) {
            return;
        }
        try {
            renderTemplate(cmsReq,
                    mRenewalSuccessTemplate, mRenewalSuccessFiller);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGE_ERROR_DISPLAY_TEMPLATE_1", mRenewalSuccessTemplate, e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }
        return;
    }

    protected BigInteger getRenewedCert(CertRecord certRec)
            throws EBaseException {
        BigInteger renewedCert = null;
        String serial = null;
        MetaInfo meta = certRec.getMetaInfo();

        if (meta == null) {
            logger.warn("RenewalServlet: no meta info in cert serial 0x" + certRec.getSerialNumber().toString(16));
            return null;
        }
        serial = (String) meta.get(CertRecord.META_RENEWED_CERT);
        if (serial == null) {
            logger.warn("RenewalServlet: no renewed cert in cert 0x" + certRec.getSerialNumber().toString(16));
            return null;
        }
        renewedCert = new BigInteger(serial);
        logger.info("RenewalServlet: renewed cert serial 0x" + renewedCert.toString(16) + "found for 0x" +
                        certRec.getSerialNumber().toString(16));
        return renewedCert;
    }

    /**
     * get certs to renew from agent.
     */
    private BigInteger getCertFromAgent(
            ArgBlock httpParams, X509Certificate[] certContainer)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certRepository = engine.getCertificateRepository();

        BigInteger serialno = null;
        X509Certificate cert = null;

        // get serial no
        serialno = httpParams.getValueAsBigInteger(SERIAL_NO, null);
        if (serialno == null) {
            logger.error(CMS.getLogMessage("CMSGW_MISSING_SERIALNO_FOR_RENEW"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_MISSING_SERIALNO_FOR_RENEW"));
        }
        // get cert from db
        cert = certRepository.getX509Certificate(serialno);
        if (cert == null) {
            logger.error(CMS.getLogMessage("CMSGW_MISSING_SERIALNO_FOR_RENEW_1", serialno.toString(16)));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_CERT_FOR_RENEWAL"));
        }

        certContainer[0] = cert;
        return serialno;
    }

    /**
     * get cert to renew from auth manager
     */
    private BigInteger getCertFromAuthMgr(
            AuthToken authToken, X509Certificate[] certContainer)
            throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateRepository certRepository = engine.getCertificateRepository();

        X509CertImpl cert = authToken.getInCert(AuthToken.TOKEN_CERT);

        if (cert == null) {
            logger.error(CMS.getLogMessage("CMSGW_MISSING_CERTS_RENEW_FROM_AUTHMGR"));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_MISSING_CERTS_RENEW_FROM_AUTHMGR"));
        }

        X509CertImpl certInDB = certRepository.getX509Certificate(cert.getSerialNumber());

        if (certInDB == null || !certInDB.equals(cert)) {
            logger.error("RenewalServlet: certficate from auth manager for renewal is not from this ca");
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_INVALID_CERT_FOR_RENEWAL"));
        }
        certContainer[0] = cert;
        BigInteger serialno = ((X509Certificate) cert).getSerialNumber();

        return serialno;
    }

}
