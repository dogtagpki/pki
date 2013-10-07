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
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * 'Unrevoke' a certificate. (For certificates that are on-hold only,
 * take them off-hold)
 *
 * @version $Revision$, $Date$
 */
public class DoUnrevokeTPS extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -6245049221697655642L;

    @SuppressWarnings("unused")
    private ICertificateRepository mCertDB;

    private IRequestQueue mQueue = null;
    private IPublisherProcessor mPublisherProcessor = null;
    private String errorString = "error=";
    private String o_status = "status=0";

    private final static String OFF_HOLD = "off-hold";
    private final static int OFF_HOLD_REASON = 6;
    private final static String LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST =
            "LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_5";
    private final static String LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED_7";

    public DoUnrevokeTPS() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        if (mAuthority instanceof ICertificateAuthority) {
            mCertDB = ((ICertificateAuthority) mAuthority).getCertificateRepository();
        }
        if (mAuthority instanceof ICertAuthority) {
            mPublisherProcessor = ((ICertAuthority) mAuthority).getPublisherProcessor();
        }
        mQueue = mAuthority.getRequestQueue();

        mTemplates.remove(ICMSRequest.SUCCESS);
        mRenderResult = false;
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param serialNumber Decimal serial number of certificate to unrevoke. The certificate must be revoked
     * with a revovcation reason 'on hold' for this operation to succeed. The serial number may be expressed as a hex
     * number by prefixing '0x' to the serialNumber string
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        BigInteger[] serialNumbers;
        EBaseException error = null;

        Locale[] locale = new Locale[1];

        /*
                try {
                    form = getTemplate(mFormPath, req, locale);
                } catch (IOException e) {
                    log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()));
                    throw new ECMSGWException(
                      CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
                }
        */

        try {
            serialNumbers = getSerialNumbers(req);

            //for audit log.
            IAuthToken authToken = authenticate(cmsReq);
            String authMgr = AuditFormat.NOAUTH;

            if (authToken != null) {
                authMgr =
                        authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
            } else {
                CMS.debug("DoUnrevokeTPS::process() -  authToken is null!");
                return;
            }
            String agentID = authToken.getInString("userid");
            String initiative = AuditFormat.FROMAGENT + " agentID: " + agentID
                    + " authenticated by " + authMgr;

            AuthzToken authzToken = null;

            try {
                authzToken = authorize(mAclMethod, authToken,
                            mAuthzResourceName, "unrevoke");
            } catch (EAuthzAccessDenied e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
            } catch (Exception e) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
            }

            if (authzToken == null) {
                cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
                o_status = "status=3";
                errorString = "error=unauthorized";
                String pp = o_status + "\n" + errorString;
                byte[] b = pp.getBytes();
                resp.setContentType("text/html");
                resp.setContentLength(b.length);
                OutputStream os = resp.getOutputStream();
                os.write(b);
                os.flush();
                return;
            }

            process(serialNumbers, req, resp, locale[0], initiative);
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_INVALID_SERIAL_NUM_FORMAT"));
            error = new EBaseException(CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT"));
        } catch (EBaseException e) {
            error = e;
        } catch (IOException e) {
        }

        try {
            if (error == null) {
                o_status = "status=0";
                errorString = "error=";
            } else {
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
                    CMS.getLogMessage("ADMIN_SRVLT_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    /**
     * Process X509 cert status change request
     * <P>
     *
     * (Certificate Request - an "agent" cert status change request to take a certificate off-hold)
     * <P>
     *
     * (Certificate Request Processed - an "agent" cert status change request to take a certificate off-hold)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST used when a cert status change request (e. g. -
     * "revocation") is made (before approval process)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST_PROCESSED used when a certificate status is
     * changed (taken off-hold)
     * </ul>
     *
     * @param serialNumbers the serial number of the certificate
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param locale the system locale
     * @param initiative string containing the audit format
     * @exception EBaseException an error has occurred
     */
    private void process(BigInteger[] serialNumbers,
            HttpServletRequest req,
            HttpServletResponse resp,
            Locale locale, String initiative)
            throws EBaseException {
        boolean auditRequest = true;
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = auditRequesterID(req);
        String auditSerialNumber = auditSerialNumber(serialNumbers[0].toString());
        String auditRequestType = OFF_HOLD;
        RequestStatus auditApprovalStatus = null;
        String auditReasonNum = String.valueOf(OFF_HOLD_REASON);

        try {
            String snList = "";

            // certs are for old cloning and they should be removed as soon as possible
            X509CertImpl[] certs = new X509CertImpl[serialNumbers.length];
            for (int i = 0; i < serialNumbers.length; i++) {
                certs[i] = (X509CertImpl) getX509Certificate(serialNumbers[i]);
                if (snList.length() > 0)
                    snList += ", ";
                snList += "0x" + serialNumbers[i].toString(16);
            }

            IRequest unrevReq = mQueue.newRequest(IRequest.UNREVOCATION_REQUEST);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CERT_STATUS_CHANGE_REQUEST,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditRequesterID,
                        auditSerialNumber,
                        auditRequestType);

            audit(auditMessage);

            unrevReq.setExtData(IRequest.REQ_TYPE, IRequest.UNREVOCATION_REQUEST);
            unrevReq.setExtData(IRequest.OLD_SERIALS, serialNumbers);
            unrevReq.setExtData(IRequest.REQUESTOR_TYPE, IRequest.REQUESTOR_AGENT);

            // change audit processing from "REQUEST" to "REQUEST_PROCESSED"
            // to distinguish which type of signed audit log message to save
            // as a failure outcome in case an exception occurs
            auditRequest = false;

            mQueue.processRequest(unrevReq);

            // retrieve the request status
            auditApprovalStatus = unrevReq.getRequestStatus();

            RequestStatus status = unrevReq.getRequestStatus();
            String type = unrevReq.getRequestType();

            if ((status == RequestStatus.COMPLETE)
                    || ((type.equals(IRequest.CLA_UNCERT4CRL_REQUEST)) && (status == RequestStatus.SVC_PENDING))) {

                Integer result = unrevReq.getExtDataInInteger(IRequest.RESULT);

                if (result != null && result.equals(IRequest.RES_SUCCESS)) {
                    if (certs[0] != null) {
                        mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                                AuditFormat.LEVEL,
                                AuditFormat.DOUNREVOKEFORMAT,
                                new Object[] {
                                        unrevReq.getRequestId(),
                                        initiative,
                                        "completed",
                                        certs[0].getSubjectDN(),
                                        "0x" + serialNumbers[0].toString(16) }
                                );
                    }
                } else {
                    String error = unrevReq.getExtDataInString(IRequest.ERROR);

                    if (error != null) {
                        o_status = "status=3";
                        errorString = "error=" + error;
                        if (certs[0] != null) {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.DOUNREVOKEFORMAT,
                                    new Object[] {
                                            unrevReq.getRequestId(),
                                            initiative,
                                            "completed with error: " +
                                                    error,
                                            certs[0].getSubjectDN(),
                                            "0x" + serialNumbers[0].toString(16) }
                                    );
                        }
                    }
                }

                Integer updateCRLResult =
                        unrevReq.getExtDataInInteger(IRequest.CRL_UPDATE_STATUS);

                if (updateCRLResult != null) {
                    if (!updateCRLResult.equals(IRequest.RES_SUCCESS)) {
                        String crlError =
                                unrevReq.getExtDataInString(IRequest.CRL_UPDATE_ERROR);

                        if (crlError != null) {
                            o_status = "status=3";
                            errorString = "error=" + crlError;
                        }
                    }
                    // let known crl publishing status too.
                    Integer publishCRLResult =
                            unrevReq.getExtDataInInteger(IRequest.CRL_PUBLISH_STATUS);

                    if (publishCRLResult != null) {
                        if (!publishCRLResult.equals(IRequest.RES_SUCCESS)) {
                            String publError =
                                    unrevReq.getExtDataInString(IRequest.CRL_PUBLISH_ERROR);

                            if (publError != null) {
                                o_status = "status=3";
                                errorString = "error=" + publError;
                            }
                        }
                    }
                }

                // let known update and publish status of all crls.
                Enumeration<ICRLIssuingPoint> otherCRLs =
                        ((ICertificateAuthority) mAuthority).getCRLIssuingPoints();

                while (otherCRLs.hasMoreElements()) {
                    ICRLIssuingPoint crl = otherCRLs.nextElement();
                    String crlId = crl.getId();

                    if (crlId.equals(ICertificateAuthority.PROP_MASTER_CRL))
                        continue;
                    String updateStatusStr = crl.getCrlUpdateStatusStr();
                    Integer updateResult = unrevReq.getExtDataInInteger(updateStatusStr);

                    if (updateResult != null) {
                        if (!updateResult.equals(IRequest.RES_SUCCESS)) {
                            String updateErrorStr = crl.getCrlUpdateErrorStr();
                            String error =
                                    unrevReq.getExtDataInString(updateErrorStr);

                            if (error != null) {
                                o_status = "status=3";
                                errorString = "error=" + error;
                            }
                        }
                        String publishStatusStr = crl.getCrlPublishStatusStr();
                        Integer publishResult =
                                unrevReq.getExtDataInInteger(publishStatusStr);

                        if (publishResult == null)
                            continue;
                        if (!publishResult.equals(IRequest.RES_SUCCESS)) {
                            String publishErrorStr =
                                    crl.getCrlPublishErrorStr();

                            String error =
                                    unrevReq.getExtDataInString(publishErrorStr);

                            if (error != null) {
                                o_status = "status=3";
                                errorString = "error=" + error;
                            }
                        }
                    }
                }

                if (mPublisherProcessor != null && mPublisherProcessor.ldapEnabled()) {
                    Integer[] ldapPublishStatus =
                            unrevReq.getExtDataInIntegerArray("ldapPublishStatus");

                    if (ldapPublishStatus != null) {
                        if (ldapPublishStatus[0] != IRequest.RES_SUCCESS) {
                            o_status = "status=3";
                            errorString = "error=Problem in publishing to LDAP";
                        }
                    }
                } else if (mPublisherProcessor == null || (!mPublisherProcessor.ldapEnabled())) {
                    o_status = "status=3";
                    errorString = "error=LDAP Publisher not enabled";
                }

            } else if (status == RequestStatus.PENDING) {
                o_status = "status=2";
                errorString = "error=" + status.toString();
                if (certs[0] != null) {
                    mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                            AuditFormat.LEVEL,
                            AuditFormat.DOUNREVOKEFORMAT,
                            new Object[] {
                                    unrevReq.getRequestId(),
                                    initiative,
                                    "pending",
                                    certs[0].getSubjectDN(),
                                    "0x" + serialNumbers[0].toString(16) }
                            );
                }
            } else {
                o_status = "status=2";
                errorString = "error=Undefined request status";

                if (certs[0] != null) {
                    mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                            AuditFormat.LEVEL,
                            AuditFormat.DOUNREVOKEFORMAT,
                            new Object[] {
                                    unrevReq.getRequestId(),
                                    initiative,
                                    status.toString(),
                                    certs[0].getSubjectDN(),
                                    "0x" + serialNumbers[0].toString(16) }
                            );
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

        } catch (EBaseException eAudit1) {
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
        }

        return;
    }

    private BigInteger[] getSerialNumbers(HttpServletRequest req)
            throws NumberFormatException {
        String serialNumString = req.getParameter("serialNumber");

        StringTokenizer snList = new StringTokenizer(serialNumString, " ");
        Vector<BigInteger> biList = new Vector<BigInteger>();
        while (snList.hasMoreTokens()) {
            String snStr = snList.nextToken();
            if (snStr != null) {
                snStr = snStr.trim();
                BigInteger bi;
                if (snStr.startsWith("0x") || snStr.startsWith("0X")) {
                    bi = new BigInteger(snStr.substring(2), 16);
                } else {
                    bi = new BigInteger(snStr);
                }
                if (bi.compareTo(BigInteger.ZERO) < 0) {
                    throw new NumberFormatException();
                }
                biList.addElement(bi);
            } else {
                throw new NumberFormatException();
            }
        }
        if (biList.size() < 1) {
            throw new NumberFormatException();
        }

        BigInteger[] biNumbers = new BigInteger[biList.size()];
        for (int i = 0; i < biList.size(); i++) {
            biNumbers[i] = biList.elementAt(i);
        }

        return biNumbers;
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
}
