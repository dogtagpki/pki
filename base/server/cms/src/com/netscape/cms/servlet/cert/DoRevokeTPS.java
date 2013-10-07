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
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.InvalidityDateExtension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Revoke a Certificate
 *
 * @version $Revision$, $Date$
 */
public class DoRevokeTPS extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -2980600514636454836L;
    private final static String TPL_FILE = "revocationResult.template";

    private ICertificateRepository mCertDB = null;
    private String mFormPath = null;
    private IRequestQueue mQueue = null;
    private IPublisherProcessor mPublisherProcessor = null;
    private String errorString = "error=";
    private String o_status = "status=0";
    private int mTimeLimits = 30; /* in seconds */

    private final static String REVOKE = "revoke";
    private final static String ON_HOLD = "on-hold";
    private final static int ON_HOLD_REASON = 6;
    private final static String LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST =
            "LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_5";
    private final static String LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED_7";

    public DoRevokeTPS() {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template
     * file "revocationResult.template" to render the result
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        if (mAuthority instanceof ICertificateAuthority) {
            mCertDB = ((ICertificateAuthority) mAuthority).getCertificateRepository();
        }
        if (mAuthority instanceof ICertAuthority) {
            mPublisherProcessor = ((ICertAuthority) mAuthority).getPublisherProcessor();
        }
        mQueue = mAuthority.getRequestQueue();

        mTemplates.remove(ICMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
        mRenderResult = false;

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
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);
        CMS.debug("DoRevokeTPS after authenticate");

        String revokeAll = null;
        int totalRecordCount = -1;
        EBaseException error = null;
        int reason = -1;
        boolean authorized = true;
        Date invalidityDate = null;
        Locale[] locale = new Locale[1];

        CMS.debug("DoRevokeTPS before getTemplate");
        try {
            @SuppressWarnings("unused")
            CMSTemplate form = getTemplate(mFormPath, req, locale); // check for errors
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
        } catch (Exception e) {
            CMS.debug("DoRevokeTPS getTemplate failed");
            throw new EBaseException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
        }

        CMS.debug("DoRevokeTPS after getTemplate");
        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
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
            if (req.getParameter("invalidityDate") != null) {
                long l = Long.parseLong(req.getParameter(
                            "invalidityDate"));

                if (l > 0) {
                    invalidityDate = new Date(l);
                }
            }
            revokeAll = req.getParameter("revokeAll");
            String comments = req.getParameter(IRequest.REQUESTOR_COMMENTS);

            //for audit log.
            String initiative = null;

            String authMgr = AuditFormat.NOAUTH;

            AuthzToken authzToken = null;

            try {
                authzToken = authorize(mAclMethod, authToken,
                            mAuthzResourceName, "revoke");
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

            if (mAuthMgr != null && mAuthMgr.equals(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID)) {
                if (authToken != null) {
                    authMgr = authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
                    String agentID = authToken.getInString("userid");

                    initiative = AuditFormat.FROMAGENT + " agentID: " + agentID +
                            " authenticated by " + authMgr;
                }
            } else {
                CMS.debug("DoRevokeTPS: Missing authentication manager");
                o_status = "status=1";
                errorString = "errorString=Missing authentication manager.";
            }

            if (authorized) {
                process(argSet, header, reason, invalidityDate, initiative, req,
                        resp, revokeAll, totalRecordCount, comments, locale[0]);
            }
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"));
            error = new EBaseException(CMS.getLogMessage("BASE_INVALID_NUMBER_FORMAT"));
        } catch (EBaseException e) {
            error = e;
        }

        try {
            if (!authorized) {
                o_status = "status=3";
                errorString = "error=unauthorized";
            } else if (error != null) {
                o_status = "status=3";
                errorString = "error=" + error.toString();
            }

            String pp = o_status + "\n" + errorString;
            byte[] b = pp.getBytes();
            resp.setContentType("text/html");
            resp.setContentLength(b.length);
            OutputStream os = resp.getOutputStream();
            os.write(b);
            os.flush();
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
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
     * @param revokeAll string containing information on all of the
     *            certificates to be revoked
     * @param totalRecordCount total number of records (verified and unverified)
     * @param comments string containing certificate comments
     * @param locale the system locale
     * @exception EBaseException an error has occurred
     */
    private void process(CMSTemplateParams argSet, IArgBlock header,
            int reason, Date invalidityDate,
            String initiative,
            HttpServletRequest req,
            HttpServletResponse resp,
            String revokeAll,
            int totalRecordCount,
            String comments,
            Locale locale)
            throws EBaseException {
        boolean auditRequest = true;
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(req);
        String auditSerialNumber = auditSerialNumber(null);
        String auditRequestType = auditRequestType(reason);
        RequestStatus auditApprovalStatus = null;
        String auditReasonNum = String.valueOf(reason);

        if (revokeAll != null) {
            CMS.debug("DoRevokeTPS.process revokeAll" + revokeAll);

            String serial = "";
            String[] tokens;
            tokens = revokeAll.split("=");

            if (tokens.length == 2) {
                serial = tokens[1];
                //remove the trailing paren
                if (serial.endsWith(")")) {
                    serial = serial.substring(0, serial.length() - 1);
                }
                auditSerialNumber = serial;
            }
        }

        long startTime = CMS.getCurrentDate().getTime();

        try {
            int count = 0;
            Vector<X509CertImpl> oldCertsV = new Vector<X509CertImpl>();
            Vector<RevokedCertImpl> revCertImplsV = new Vector<RevokedCertImpl>();

            // Construct a CRL reason code extension.
            RevocationReason revReason = RevocationReason.fromInt(reason);
            CRLReasonExtension crlReasonExtn = new CRLReasonExtension(revReason);

            // Construct a CRL invalidity date extension.
            InvalidityDateExtension invalidityDateExtn = null;

            if (invalidityDate != null) {
                invalidityDateExtn = new InvalidityDateExtension(invalidityDate);
            }

            // Construct a CRL extension for this request.
            CRLExtensions entryExtn = new CRLExtensions();

            if (crlReasonExtn != null) {
                entryExtn.set(crlReasonExtn.getName(), crlReasonExtn);
            }
            if (invalidityDateExtn != null) {
                entryExtn.set(invalidityDateExtn.getName(), invalidityDateExtn);
            }

            Enumeration<ICertRecord> e = mCertDB.searchCertificates(revokeAll,
                    totalRecordCount, mTimeLimits);

            boolean alreadyRevokedCertFound = false;
            boolean badCertsRequested = false;
            while (e != null && e.hasMoreElements()) {
                ICertRecord rec = e.nextElement();

                if (rec == null) {
                    badCertsRequested = true;
                    continue;
                }
                X509CertImpl xcert = rec.getCertificate();
                IArgBlock rarg = CMS.createArgBlock();

                // we do not want to revoke the CA certificate accidentially
                if (xcert != null && isSystemCertificate(xcert.getSerialNumber())) {
                    CMS.debug("DoRevokeTPS: skipped revocation request for system certificate "
                            + xcert.getSerialNumber());
                    badCertsRequested = true;
                    continue;
                }

                if (xcert != null) {
                    rarg.addStringValue("serialNumber",
                            xcert.getSerialNumber().toString(16));

                    if (rec.getStatus().equals(ICertRecord.STATUS_REVOKED)) {
                        alreadyRevokedCertFound = true;
                        CMS.debug("Certificate 0x" + xcert.getSerialNumber().toString(16) + " has been revoked.");
                    } else {
                        oldCertsV.addElement(xcert);

                        RevokedCertImpl revCertImpl =
                                new RevokedCertImpl(xcert.getSerialNumber(),
                                        CMS.getCurrentDate(), entryExtn);

                        revCertImplsV.addElement(revCertImpl);
                        CMS.debug("Certificate 0x" + xcert.getSerialNumber().toString(16) + " is going to be revoked.");
                        count++;
                    }
                } else {
                    badCertsRequested = true;
                }
            }

            if (count == 0) {
                // Situation where no certs were reoked here, but some certs
                // requested happened to be already revoked. Don't return error.
                if (alreadyRevokedCertFound == true && badCertsRequested == false) {
                    CMS.debug("Only have previously revoked certs in the list.");
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRequesterID,
                            auditSerialNumber,
                            auditRequestType);

                    audit(auditMessage);
                    return;
                }

                errorString = "error=No certificates are revoked.";
                o_status = "status=2";
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_REV_CERTS_ZERO"));

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditSerialNumber,
                            auditRequestType);

                audit(auditMessage);

                throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED"));
            }

            X509CertImpl[] oldCerts = new X509CertImpl[count];
            RevokedCertImpl[] revCertImpls = new RevokedCertImpl[count];

            for (int i = 0; i < count; i++) {
                oldCerts[i] = oldCertsV.elementAt(i);
                revCertImpls[i] = revCertImplsV.elementAt(i);
            }

            IRequest revReq =
                    mQueue.newRequest(IRequest.REVOCATION_REQUEST);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRequesterID,
                        auditSerialNumber,
                        auditRequestType);

            audit(auditMessage);

            revReq.setExtData(IRequest.CERT_INFO, revCertImpls);
            revReq.setExtData(IRequest.REQ_TYPE, IRequest.REVOCATION_REQUEST);
            if (initiative.equals(AuditFormat.FROMUSER)) {
                revReq.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_EE);
            } else {
                revReq.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_AGENT);
            }
            revReq.setExtData(IRequest.OLD_CERTS, oldCerts);
            if (comments != null) {
                revReq.setExtData(IRequest.REQUESTOR_COMMENTS, comments);
            }
            revReq.setExtData(IRequest.REVOKED_REASON,
                    Integer.valueOf(reason));

            // change audit processing from "REQUEST" to "REQUEST_PROCESSED"
            // to distinguish which type of signed audit log message to save
            // as a failure outcome in case an exception occurs
            auditRequest = false;

            mQueue.processRequest(revReq);

            // retrieve the request status
            auditApprovalStatus = revReq.getRequestStatus();

            RequestStatus stat = revReq.getRequestStatus();
            String type = revReq.getRequestType();

            // The SVC_PENDING check has been added for the Cloned CA request
            // that is meant for the Master CA. From Clone's point of view
            // the request is complete
            if ((stat == RequestStatus.COMPLETE)
                    || ((type.equals(IRequest.CLA_CERT4CRL_REQUEST)) && (stat == RequestStatus.SVC_PENDING))) {
                // audit log the error
                Integer result = revReq.getExtDataInInteger(IRequest.RESULT);

                if (result.equals(IRequest.RES_ERROR)) {
                    String[] svcErrors =
                            revReq.getExtDataInStringArray(IRequest.SVCERRORS);

                    if (svcErrors != null && svcErrors.length > 0) {
                        for (int i = 0; i < svcErrors.length; i++) {
                            String err = svcErrors[i];

                            if (err != null) {
                                //cmsReq.setErrorDescription(err);
                                for (int j = 0; j < count; j++) {
                                    if (oldCerts[j] instanceof X509CertImpl) {
                                        X509CertImpl cert = oldCerts[j];

                                        if (oldCerts[j] != null) {
                                            mLogger.log(ILogger.EV_AUDIT,
                                                    ILogger.S_OTHER,
                                                    AuditFormat.LEVEL,
                                                    AuditFormat.DOREVOKEFORMAT,
                                                    new Object[] {
                                                            revReq.getRequestId(),
                                                            initiative,
                                                            "completed with error: " +
                                                                    err,
                                                            cert.getSubjectDN(),
                                                            cert.getSerialNumber().toString(16),
                                                            RevocationReason.fromInt(reason).toString() }
                                                    );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // store a message in the signed audit log file
                    // if and only if "auditApprovalStatus" is
                    // "complete", "revoked", or "canceled"
                    if (auditApprovalStatus == RequestStatus.COMPLETE ||
                            auditApprovalStatus == RequestStatus.REJECTED ||
                            auditApprovalStatus == RequestStatus.CANCELED) {
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    auditSerialNumber,
                                    auditRequestType,
                                    auditReasonNum,
                                    auditApprovalStatus == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : auditApprovalStatus.toString());

                        audit(auditMessage);
                    }

                    return;
                }

                long endTime = CMS.getCurrentDate().getTime();

                // audit log the success.
                for (int j = 0; j < count; j++) {
                    if (oldCerts[j] != null) {
                        if (oldCerts[j] instanceof X509CertImpl) {
                            X509CertImpl cert = oldCerts[j];

                            mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.DOREVOKEFORMAT,
                                    new Object[] {
                                            revReq.getRequestId(),
                                            initiative,
                                            "completed",
                                            cert.getSubjectDN(),
                                            cert.getSerialNumber().toString(16),
                                            RevocationReason.fromInt(reason).toString()
                                                    + " time: " + (endTime - startTime) }
                                    );
                        }
                    }
                }

                header.addStringValue("revoked", "yes");

                Integer updateCRLResult =
                        revReq.getExtDataInInteger(IRequest.CRL_UPDATE_STATUS);

                if (updateCRLResult != null) {
                    if (!updateCRLResult.equals(IRequest.RES_SUCCESS)) {

                        o_status = "status=3";
                        if (revReq.getExtDataInString(IRequest.CRL_UPDATE_ERROR) != null) {
                            errorString = "error=Update CRL Error.";
                            // 3 means miscellaneous
                        }
                    }
                    // let known crl publishing status too.
                    Integer publishCRLResult =
                            revReq.getExtDataInInteger(IRequest.CRL_PUBLISH_STATUS);

                    if (publishCRLResult != null) {
                        if (!publishCRLResult.equals(IRequest.RES_SUCCESS)) {
                            String publError =
                                    revReq.getExtDataInString(IRequest.CRL_PUBLISH_ERROR);

                            o_status = "status=3";
                            if (publError != null) {
                                errorString = "error=" + publError;
                            }
                        }
                    }
                }

                if (mAuthority instanceof ICertificateAuthority) {
                    // let known update and publish status of all crls.
                    Enumeration<ICRLIssuingPoint> otherCRLs =
                            ((ICertificateAuthority) mAuthority).getCRLIssuingPoints();

                    while (otherCRLs.hasMoreElements()) {
                        ICRLIssuingPoint crl = otherCRLs.nextElement();
                        String crlId = crl.getId();

                        if (crlId.equals(ICertificateAuthority.PROP_MASTER_CRL))
                            continue;
                        String updateStatusStr = crl.getCrlUpdateStatusStr();
                        Integer updateResult = revReq.getExtDataInInteger(updateStatusStr);

                        if (updateResult != null) {
                            if (!updateResult.equals(IRequest.RES_SUCCESS)) {
                                String updateErrorStr = crl.getCrlUpdateErrorStr();

                                CMS.debug("DoRevoke: " + CMS.getLogMessage("ADMIN_SRVLT_ADDING_HEADER_NO",
                                        updateStatusStr));
                                String error =
                                        revReq.getExtDataInString(updateErrorStr);

                                o_status = "status=3";
                                if (error != null) {
                                    errorString = "error=" + error;
                                }
                            }
                            String publishStatusStr = crl.getCrlPublishStatusStr();
                            Integer publishResult =
                                    revReq.getExtDataInInteger(publishStatusStr);

                            if (publishResult == null)
                                continue;
                            if (!publishResult.equals(IRequest.RES_SUCCESS)) {
                                String publishErrorStr =
                                        crl.getCrlPublishErrorStr();

                                String error =
                                        revReq.getExtDataInString(publishErrorStr);

                                o_status = "status=3";
                                if (error != null) {
                                    errorString = "error=Publish CRL Status Error.";
                                }
                            }
                        }
                    }
                }

                if (mPublisherProcessor != null && mPublisherProcessor.ldapEnabled()) {
                    header.addStringValue("dirEnabled", "yes");

                    // add crl publishing status.
                    String publError =
                            revReq.getExtDataInString(IRequest.CRL_PUBLISH_ERROR);

                    if (publError != null) {
                        errorString = "error=" + publError;
                        o_status = "status=3";
                    }
                } else if (mPublisherProcessor == null && mPublisherProcessor.ldapEnabled()) {
                    errorString = "error=LDAP publishing not enabled.";
                    o_status = "status=3";
                }
            } else {
                if (stat == RequestStatus.PENDING || stat == RequestStatus.REJECTED) {
                    o_status = "status=2";
                    errorString = "error=" + stat.toString();
                } else {
                    o_status = "status=2";
                    errorString = "error=Undefined request status";
                }
                Vector<String> errors = revReq.getExtDataInStringVector(IRequest.ERRORS);
                if (errors != null) {
                    StringBuffer errInfo = new StringBuffer();

                    for (int i = 0; i < errors.size(); i++) {
                        errInfo.append(errors.elementAt(i));
                        errInfo.append("\n");
                    }
                    o_status = "status=2";
                    errorString = "error=" + errInfo.toString();

                } else if (stat == RequestStatus.PENDING) {
                    o_status = "status=2";
                    errorString = "error=Request pending";
                } else {
                    o_status = "status=2";
                    errorString = "error=Undefined request status";
                }

                // audit log the pending, revoked and rest
                for (int j = 0; j < count; j++) {
                    if (oldCerts[j] != null) {
                        if (oldCerts[j] instanceof X509CertImpl) {
                            X509CertImpl cert = oldCerts[j];

                            mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.DOREVOKEFORMAT,
                                    new Object[] {
                                            revReq.getRequestId(),
                                            initiative,
                                            stat.toString(),
                                            cert.getSubjectDN(),
                                            cert.getSerialNumber().toString(16),
                                            RevocationReason.fromInt(reason).toString() }
                                    );
                        }
                    }
                }
            }

            // store a message in the signed audit log file
            // if and only if "auditApprovalStatus" is
            // "complete", "revoked", or "canceled"
            if (auditApprovalStatus == RequestStatus.COMPLETE ||
                    auditApprovalStatus == RequestStatus.REJECTED ||
                    auditApprovalStatus == RequestStatus.CANCELED) {
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRequesterID,
                            auditSerialNumber,
                            auditRequestType,
                            auditReasonNum,
                            auditApprovalStatus == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : auditApprovalStatus.toString());

                audit(auditMessage);
            }
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, "error " + e);

            if (auditRequest) {
                // store a "CERT_STATUS_CHANGE_REQUEST" failure
                // message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditSerialNumber,
                            auditRequestType);

                audit(auditMessage);
            } else {
                // store a "CERT_STATUS_CHANGE_REQUEST_PROCESSED" failure
                // message in the signed audit log file
                // if and only if "auditApprovalStatus" is
                // "complete", "revoked", or "canceled"
                if (auditApprovalStatus == RequestStatus.COMPLETE ||
                        auditApprovalStatus == RequestStatus.REJECTED ||
                        auditApprovalStatus == RequestStatus.CANCELED) {
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditSerialNumber,
                                auditRequestType,
                                auditReasonNum,
                                auditApprovalStatus == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : auditApprovalStatus.toString());

                    audit(auditMessage);
                }
            }

            throw e;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED_1", e.toString()));

            if (auditRequest) {
                // store a "CERT_STATUS_CHANGE_REQUEST" failure
                // message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditSerialNumber,
                            auditRequestType);

                audit(auditMessage);
            } else {
                // store a "CERT_STATUS_CHANGE_REQUEST_PROCESSED" failure
                // message in the signed audit log file
                // if and only if "auditApprovalStatus" is
                // "complete", "revoked", or "canceled"
                if (auditApprovalStatus == RequestStatus.COMPLETE ||
                        auditApprovalStatus == RequestStatus.REJECTED ||
                        auditApprovalStatus == RequestStatus.CANCELED) {
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditSerialNumber,
                                auditRequestType,
                                auditReasonNum,
                                auditApprovalStatus == null ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : auditApprovalStatus.toString());

                    audit(auditMessage);
                }
            }

            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_MARKING_CERT_REVOKED"));
        }

        return;
    }

    /**
     * Signed Audit Log Requester ID
     *
     * This method is called to obtain the "RequesterID" for
     * a signed audit log message.
     * <P>
     *
     * @param req HTTP request
     * @return id string containing the signed audit log message RequesterID
     */
    private String auditRequesterID(HttpServletRequest req) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String requesterID = null;

        // Obtain the requesterID
        requesterID = req.getParameter("requestId");

        if (requesterID != null) {
            requesterID = requesterID.trim();
        } else {
            requesterID = ILogger.UNIDENTIFIED;
        }

        return requesterID;
    }

    /**
     * Signed Audit Log Serial Number
     *
     * This method is called to obtain the serial number of the certificate
     * whose status is to be changed for a signed audit log message.
     * <P>
     *
     * @param eeSerialNumber a string containing the un-normalized serialNumber
     * @return id string containing the signed audit log message RequesterID
     */
    private String auditSerialNumber(String eeSerialNumber) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String serialNumber = null;

        // Normalize the serialNumber
        if (eeSerialNumber != null) {
            serialNumber = eeSerialNumber.trim();

            // convert it to hexadecimal
            serialNumber = "0x" + (new BigInteger(serialNumber)).toString(16);
        } else {
            serialNumber = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        return serialNumber;
    }

    /**
     * Signed Audit Log Request Type
     *
     * This method is called to obtain the "Request Type" for
     * a signed audit log message.
     * <P>
     *
     * @param reason an integer denoting the revocation reason
     * @return string containing REVOKE or ON_HOLD
     */
    private String auditRequestType(int reason) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String requestType = null;

        // Determine the revocation type based upon the revocation reason
        if (reason == ON_HOLD_REASON) {
            requestType = ON_HOLD;
        } else {
            requestType = REVOKE;
        }

        return requestType;
    }
}
