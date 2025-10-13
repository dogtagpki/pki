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
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.ca.CRLIssuingPoint;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.ldap.CAPublisherProcessor;
import com.netscape.cmscore.request.Request;

/**
 * Revoke a Certificate
 */
@WebServlet(
        name = "caDoRevoke",
        urlPatterns = "/ee/ca/doRevoke",
        initParams = {
                @WebInitParam(name="GetClientCert", value="false"),
                @WebInitParam(name="AuthzMgr",      value="BasicAclAuthz"),
                @WebInitParam(name="authority",     value="ca"),
                @WebInitParam(name="templatePath",  value="/ee/ca/revocationResult.template"),
                @WebInitParam(name="interface",     value="ee"),
                @WebInitParam(name="ID",            value="caDoRevoke"),
                @WebInitParam(name="resourceID",    value="certServer.ee.certificates")
        }
)
public class DoRevoke extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(DoRevoke.class);

    private static final long serialVersionUID = 1693115906265904238L;
    private final static String TPL_FILE = "revocationResult.template";

    private CertificateRepository mCertDB;
    private String mFormPath = null;
    private CAPublisherProcessor mPublisherProcessor;
    private int mTimeLimits = 30; /* in seconds */

    public DoRevoke() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template
     * file "revocationResult.template" to render the result
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        CAEngine engine = CAEngine.getInstance();

        mFormPath = "/ca/" + TPL_FILE;

        mCertDB = engine.getCertificateRepository();
        mPublisherProcessor = engine.getPublisherProcessor();

        mTemplates.remove(CMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        /* Server-Side time limit */
        try {
            mTimeLimits = Integer.parseInt(sc.getInitParameter("timeLimits"));
        } catch (Exception e) {
            /* do nothing, just use the default if integer parsing failed */
        }
    }

    /**
     * Serves HTTP request. The http parameters used by this request are as follows:
     *
     * <pre>
     * serialNumber Serial number of certificate to revoke (in HEX)
     * revocationReason Revocation reason (Described below)
     * totalRecordCount [number]
     * verifiedRecordCount [number]
     * invalidityDate [number of seconds in Jan 1,1970]
     *
     * </pre>
     *
     * revocationReason can be one of these values:
     *
     * <pre>
     * 0 = Unspecified   (default)
     * 1 = Key compromised
     * 2 = CA key compromised
     * 3 = Affiliation changed
     * 4 = Certificate superseded
     * 5 = Cessation of operation
     * 6 = Certificate is on hold
     * </pre>
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        AuthToken authToken = authenticate(cmsReq);

        String revokeAll = null;
        int totalRecordCount = -1;
        int verifiedRecordCount = -1;
        EBaseException error = null;
        int reason = -1;
        boolean authorized = true;
        Date invalidityDate = null;
        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"), e);
        }

        ArgBlock header = new ArgBlock();
        ArgBlock ctx = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        try {
            if (req.getParameter("revocationReason") != null) {
                reason = Integer.parseInt(req.getParameter(
                                "revocationReason"));
            }
            if (req.getParameter("totalRecordCount") != null) {
                totalRecordCount = Integer.parseInt(req.getParameter(
                                "totalRecordCount"));
            }
            if (req.getParameter("verifiedRecordCount") != null) {
                verifiedRecordCount = Integer.parseInt(
                            req.getParameter(
                                    "verifiedRecordCount"));
            }
            if (req.getParameter("invalidityDate") != null) {
                long l = Long.parseLong(req.getParameter(
                            "invalidityDate"));

                if (l > 0) {
                    invalidityDate = new Date(l);
                }
            }
            revokeAll = req.getParameter("revokeAll");

            String comments = req.getParameter(Request.REQUESTOR_COMMENTS);
            String eeSubjectDN = null;
            String eeSerialNumber = null;

            //for audit log.
            String initiative = null;

            String authMgr = AuditFormat.NOAUTH;

            authToken = authenticate(req);

            AuthzToken authzToken = null;

            try {
                authzToken = authorize(mAclMethod, authToken,
                            mAuthzResourceName, "revoke");
            } catch (EAuthzAccessDenied e) {
                logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);

            } catch (Exception e) {
                logger.warn(CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()), e);
            }

            if (authzToken == null) {
                cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
                return;
            }

            if (mAuthMgr != null && mAuthMgr.equals(AuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
                if (authToken != null) {
                    // Request is from agent.

                    String serialNumber = req.getParameter("serialNumber");
                    getSSLClientCertificate(req); // throw exception on error

                    if (serialNumber != null) {
                        // Agent has null subject DN.
                        eeSerialNumber = serialNumber;
                    }

                    authMgr = authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
                    String agentID = authToken.getInString("userid");

                    initiative = AuditFormat.FROMAGENT + " agentID: " + agentID +
                            " authenticated by " + authMgr;
                }
            } else {
                // Request is from user.
                initiative = AuditFormat.FROMUSER;

                String serialNumber = req.getParameter("serialNumber");
                X509CertImpl sslCert = (X509CertImpl) getSSLClientCertificate(req);

                if (serialNumber == null || sslCert == null ||
                        !(serialNumber.equals(sslCert.getSerialNumber().toString(16)))) {
                    throw new ForbiddenException("Invalid serial number.");
                }
                eeSubjectDN = sslCert.getSubjectName().toString();
                eeSerialNumber = sslCert.getSerialNumber().toString();
            }

            BigInteger serialNumber = parseSerialNumber(eeSerialNumber);

            process(argSet, header, reason, invalidityDate, initiative,
                    req, resp, verifiedRecordCount, revokeAll,
                    totalRecordCount, serialNumber, eeSubjectDN,
                    comments, locale[0]);

        } catch (NumberFormatException e) {
            logger.error(CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"), e);
            error = new EBaseException(CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"), e);

        } catch (ForbiddenException e) {
            authorized = false;

        } catch (EBaseException e) {
            error = e;
        }

        /*
         catch (Exception e) {
         noError = false;
         header.addStringValue(OUT_ERROR,
         MessageFormatter.getLocalizedString(
         errorlocale[0],
         BaseResources.class.getName(),
         BaseResources.INTERNAL_ERROR_1,
         e.toString()));
         }
         */

        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null && authorized) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                    outputXML(resp, argSet);
                } else {
                    resp.setContentType("text/html");
                    form.renderOutput(out, argSet);
                    cmsReq.setStatus(CMSRequest.SUCCESS);
                }
            } else if (!authorized) {
                cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                cmsReq.setError(error);
            }

        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"), e);
        }
    }

    /**
     * Process cert status change request
     * <P>
     *
     * (Certificate Request - either an "agent" cert status change request, or an "EE" cert status change request)
     * <P>
     *
     * (Certificate Request Processed - either an "agent" cert status change request, or an "EE" cert status change
     * request)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST used when a cert status change request (e. g. -
     * "revocation") is made (before approval process)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED used when a certificate status is
     * changed (revoked, expired, on-hold, off-hold)
     * </ul>
     *
     * @param argSet CMS template parameters
     * @param header argument block
     * @param reason revocation reason (0 - Unspecified, 1 - Key compromised,
     *            2 - CA key compromised; should not be used, 3 - Affiliation changed,
     *            4 - Certificate superceded, 5 - Cessation of operation, or
     *            6 - Certificate is on hold)
     * @param invalidityDate certificate validity date
     * @param initiative string containing the audit format
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param verifiedRecordCount number of verified records
     * @param revokeAll string containing information on all of the
     *            certificates to be revoked
     * @param totalRecordCount total number of records (verified and unverified)
     * @param eeSerialNumber BigInteger containing the end-entity certificate
     *            serial number
     * @param eeSubjectDN string containing the end-entity certificate subject
     *            distinguished name (DN)
     * @param comments string containing certificate comments
     * @param locale the system locale
     * @exception EBaseException an error has occurred
     */
    private void process(CMSTemplateParams argSet, ArgBlock header,
            int reason, Date invalidityDate,
            String initiative,
            HttpServletRequest req,
            HttpServletResponse resp,
            int verifiedRecordCount,
            String revokeAll,
            int totalRecordCount,
            BigInteger eeSerialNumber,
            String eeSubjectDN,
            String comments,
            Locale locale)
            throws EBaseException {

        logger.debug("DoRevoke: eeSerialNumber: " + eeSerialNumber);
        long startTime = new Date().getTime();

        CAEngine engine = CAEngine.getInstance();

        RevocationProcessor processor =
                new RevocationProcessor(servletConfig.getServletName(), getLocale(req));
        processor.setCMSEngine(engine);
        processor.init();

        processor.setStartTime(startTime);
        processor.setInitiative(initiative);
        processor.setSerialNumber(eeSerialNumber == null ? null : new CertId(eeSerialNumber));

        RevocationReason revReason = RevocationReason.valueOf(reason);
        processor.setRevocationReason(revReason);
        processor.setRequestType(
                processor.getRevocationReason() == RevocationReason.CERTIFICATE_HOLD
                        ? RevocationProcessor.ON_HOLD : RevocationProcessor.REVOKE);

        processor.setInvalidityDate(invalidityDate);
        processor.setComments(comments);

        Hashtable<BigInteger, Long> nonceMap = new Hashtable<>();
        X509Certificate clientCert = getSSLClientCertificate(req);

        processor.setAuthority(engine.getCA());

        if (engine.getEnableNonces()) {
            String nonces = req.getParameter("nonce");
            if (nonces == null) {
                throw new ForbiddenException("Missing nonce.");
            }

            // parse serial numbers and nonces
            for (String s : nonces.split(",")) {
                String[] elements = s.split(":");
                BigInteger serialNumber = new BigInteger(elements[0].trim());
                Long nonce = Long.valueOf(elements[1].trim());
                nonceMap.put(serialNumber, nonce);
            }
        }

        try {
            processor.createCRLExtension();

            Enumeration<CertRecord> e = mCertDB.searchCertificates(revokeAll, totalRecordCount, mTimeLimits);

            while (e != null && e.hasMoreElements()) {
                CertRecord targetRecord = e.nextElement();
                X509CertImpl targetCert = targetRecord.getCertificate();

                // Verify end-entity cert is not revoked.
                // TODO: This should be checked during authentication.
                if (eeSerialNumber != null &&
                    eeSerialNumber.equals(targetCert.getSerialNumber()) &&
                    targetRecord.getStatus().equals(CertRecord.STATUS_REVOKED)) {

                    String message = CMS.getLogMessage("CA_CERTIFICATE_ALREADY_REVOKED_1",
                            targetRecord.getSerialNumber().toString(16));
                    logger.error(message);

                    throw new ECMSGWException(CMS.getLogMessage("CMSGW_UNAUTHORIZED"));
                }

                ArgBlock rarg = new ArgBlock();
                rarg.addStringValue("serialNumber", targetCert.getSerialNumber().toString(16));

                try {
                    if (engine.getEnableNonces() &&
                        !processor.isMemberOfSubsystemGroup(clientCert)) {
                        // validate nonce for each certificate
                        Long nonce = nonceMap.get(targetRecord.getSerialNumber());
                        processor.validateNonce(req, "cert-revoke", targetRecord.getSerialNumber(), nonce);
                    }

                    processor.validateCertificateToRevoke(eeSubjectDN, targetRecord, false);
                    processor.addCertificateToRevoke(targetCert);
                    rarg.addStringValue("error", null);

                } catch (PKIException ex) {
                    rarg.addStringValue("error", ex.getMessage());
                }

                argSet.addRepeatRecord(rarg);
            }

            int count = processor.getCertificates().size();
            if (count == 0) {
                logger.warn("Unable to pre-process revocation request: certificate not found");
                throw new ECMSGWException(CMS.getLogMessage("CMSGW_REVOCATION_ERROR_CERT_NOT_FOUND"));
            }

            header.addIntegerValue("totalRecordCount", count);

            processor.createRevocationRequest();

            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (ForbiddenException e) {
            logger.warn("Unable to pre-process revocation request: " + e.getMessage());
            throw new EAuthzException(CMS.getUserMessage(locale, "CMS_AUTHORIZATION_ERROR"));

        } catch (EBaseException e) {
            logger.error("Unable to pre-process revocation request: " + e.getMessage(), e);
            processor.auditChangeRequest(ILogger.FAILURE);

            throw e;

        } catch (IOException e) {
            logger.error("Unable to pre-process revocation request: " + e.getMessage(), e);
            processor.auditChangeRequest(ILogger.FAILURE);

            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED"));
        }

        // change audit processing from "REQUEST" to "REQUEST_PROCESSED"
        // to distinguish which type of signed audit log message to save
        // as a failure outcome in case an exception occurs

        try {
            processor.processRevocationRequest();
            Request revReq = processor.getRequest();

            // retrieve the request status
            RequestStatus status = revReq.getRequestStatus();
            processor.setRequestStatus(status);

            String type = revReq.getRequestType();

            // The SVC_PENDING check has been added for the Cloned CA request
            // that is meant for the Master CA. From Clone's point of view
            // the request is complete

            if (status == RequestStatus.COMPLETE
                    || status == RequestStatus.SVC_PENDING
                        && type.equals(Request.CLA_CERT4CRL_REQUEST)) {

                header.addStringValue("revoked", "yes");

                Integer updateCRLResult = revReq.getExtDataInInteger(Request.CRL_UPDATE_STATUS);

                if (updateCRLResult != null) {
                    header.addStringValue("updateCRL", "yes");
                    if (updateCRLResult.equals(Request.RES_SUCCESS)) {
                        header.addStringValue("updateCRLSuccess", "yes");
                    } else {
                        header.addStringValue("updateCRLSuccess", "no");
                        String crlError = revReq.getExtDataInString(Request.CRL_UPDATE_ERROR);

                        if (crlError != null)
                            header.addStringValue("updateCRLError", crlError);
                    }

                    // let known crl publishing status too.
                    Integer publishCRLResult = revReq.getExtDataInInteger(Request.CRL_PUBLISH_STATUS);

                    if (publishCRLResult != null) {
                        if (publishCRLResult.equals(Request.RES_SUCCESS)) {
                            header.addStringValue("publishCRLSuccess", "yes");
                        } else {
                            header.addStringValue("publishCRLSuccess", "no");
                            String publError = revReq.getExtDataInString(Request.CRL_PUBLISH_ERROR);

                            if (publError != null)
                                header.addStringValue("publishCRLError", publError);
                        }
                    }
                }

                // let known update and publish status of all crls.
                for (CRLIssuingPoint crl : engine.getCRLIssuingPoints()) {
                    String crlId = crl.getId();

                    if (crlId.equals(CertificateAuthority.PROP_MASTER_CRL))
                        continue;

                    String updateStatusStr = crl.getCrlUpdateStatusStr();
                    Integer updateResult = revReq.getExtDataInInteger(updateStatusStr);

                    if (updateResult != null) {
                        if (updateResult.equals(Request.RES_SUCCESS)) {
                            logger.debug("DoRevoke: "
                                    + CMS.getLogMessage("ADMIN_SRVLT_ADDING_HEADER", updateStatusStr));
                            header.addStringValue(updateStatusStr, "yes");

                        } else {
                            String updateErrorStr = crl.getCrlUpdateErrorStr();

                            logger.debug("DoRevoke: " + CMS.getLogMessage("ADMIN_SRVLT_ADDING_HEADER_NO",
                                    updateStatusStr));
                            header.addStringValue(updateStatusStr, "no");
                            String error = revReq.getExtDataInString(updateErrorStr);

                            if (error != null)
                                header.addStringValue(updateErrorStr, error);
                        }

                        String publishStatusStr = crl.getCrlPublishStatusStr();
                        Integer publishResult = revReq.getExtDataInInteger(publishStatusStr);

                        if (publishResult == null)
                            continue;

                        if (publishResult.equals(Request.RES_SUCCESS)) {
                            header.addStringValue(publishStatusStr, "yes");

                        } else {
                            String publishErrorStr = crl.getCrlPublishErrorStr();
                            header.addStringValue(publishStatusStr, "no");
                            String error = revReq.getExtDataInString(publishErrorStr);

                            if (error != null)
                                header.addStringValue(publishErrorStr, error);
                        }
                    }
                }

                if (mPublisherProcessor != null && mPublisherProcessor.ldapEnabled()) {
                    header.addStringValue("dirEnabled", "yes");
                    Integer[] ldapPublishStatus = revReq.getExtDataInIntegerArray("ldapPublishStatus");
                    int certsToUpdate = 0;
                    int certsUpdated = 0;

                    if (ldapPublishStatus != null) {
                        certsToUpdate = ldapPublishStatus.length;
                        for (int i = 0; i < certsToUpdate; i++) {
                            if (ldapPublishStatus[i] == Request.RES_SUCCESS) {
                                certsUpdated++;
                            }
                        }
                    }

                    header.addIntegerValue("certsUpdated", certsUpdated);
                    header.addIntegerValue("certsToUpdate", certsToUpdate);

                    // add crl publishing status.
                    String publError = revReq.getExtDataInString(Request.CRL_PUBLISH_ERROR);

                    if (publError != null) {
                        header.addStringValue("crlPublishError", publError);
                    }

                } else {
                    header.addStringValue("dirEnabled", "no");
                }

                header.addStringValue("error", null);

            } else {
                if (status == RequestStatus.PENDING || status == RequestStatus.REJECTED) {
                    header.addStringValue("revoked", status.toString());
                } else {
                    header.addStringValue("revoked", "no");
                }

                Vector<String> errors = revReq.getExtDataInStringVector(Request.ERRORS);
                if (errors != null) {
                    StringBuilder errInfo = new StringBuilder();
                    for (int i = 0; i < errors.size(); i++) {
                        errInfo.append(errors.elementAt(i));
                        errInfo.append("\n");
                    }
                    header.addStringValue("error", errInfo.toString());

                } else if (status == RequestStatus.PENDING) {
                    header.addStringValue("error", "Request Pending");

                } else {
                    header.addStringValue("error", null);
                }
            }

            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            logger.error("Unable to revoke certificate: " + e.getMessage(), e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);

            throw e;
        }
    }

    /**
     * This method parses a String serial number into BigInteger.
     *
     * @param serialNumber a String containing the un-normalized serial number
     * @return a BigInteger containing the serial number
     */
    private BigInteger parseSerialNumber(String serialNumber) {

        if (StringUtils.isEmpty(serialNumber)) return null;

        // Normalize the serialNumber
        serialNumber = serialNumber.trim();

        // find out if the value is hex or decimal

        //try decimal
        try {
            return new BigInteger(serialNumber, 10);
        } catch (NumberFormatException e) {
        }

        //try hex
        try {
            return new BigInteger(serialNumber, 16);
        } catch (NumberFormatException e) {
        }

        // give up if it isn't hex or dec
        throw new NumberFormatException("Invalid serial number: "+serialNumber);
    }
}
