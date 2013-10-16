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
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.RevocationReason;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.ca.ICRLIssuingPoint;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * 'Unrevoke' a certificate. (For certificates that are on-hold only,
 * take them off-hold)
 *
 * @version $Revision$, $Date$
 */
public class DoUnrevoke extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -7978703730006036625L;
    private final static String TPL_FILE = "unrevocationResult.template";

    @SuppressWarnings("unused")
    private ICertificateRepository mCertDB;

    private String mFormPath = null;
    private IPublisherProcessor mPublisherProcessor = null;

    public DoUnrevoke() {
        super();
    }

    /**
     * initialize the servlet.
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

        mTemplates.remove(ICMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
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

        BigInteger[] serialNumber;
        EBaseException error = null;

        CMSTemplate form = null;

        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        try {
            serialNumber = getSerialNumbers(req);

            //for audit log.
            IAuthToken authToken = authenticate(cmsReq);
            String authMgr = AuditFormat.NOAUTH;

            if (authToken != null) {
                authMgr =
                        authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
            } else {
                CMS.debug("DoUnrevoke::process() -  authToken is null!");
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
                return;
            }

            process(argSet, header, serialNumber, req, resp, locale[0], initiative);

        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_INVALID_SERIAL_NUM_FORMAT"));
            error = new EBaseException(CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT"));
        } catch (EBaseException e) {
            error = e;
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                    outputXML(resp, argSet);
                } else {
                    resp.setContentType("text/html");
                    form.renderOutput(out, argSet);
                    cmsReq.setStatus(ICMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(ICMSRequest.ERROR);
                cmsReq.setError(error);
            }
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
     * @param argSet CMS template parameters
     * @param header argument block
     * @param serialNumbers the serial number of the certificate
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param locale the system locale
     * @param initiative string containing the audit format
     * @exception EBaseException an error has occurred
     */
    private void process(CMSTemplateParams argSet, IArgBlock header,
            BigInteger[] serialNumbers,
            HttpServletRequest req,
            HttpServletResponse resp,
            Locale locale, String initiative)
            throws EBaseException {

        RevocationProcessor processor = new RevocationProcessor(
                servletConfig.getServletName(), getLocale(req));

        processor.setInitiative(initiative);
        processor.setSerialNumber(auditSerialNumber(serialNumbers[0].toString()));
        processor.setRequestID(auditRequesterID(req));

        processor.setRevocationReason(RevocationReason.CERTIFICATE_HOLD);
        processor.setRequestType(RevocationProcessor.OFF_HOLD);

        if (mAuthority instanceof ICertificateAuthority) {
            processor.setAuthority((ICertificateAuthority) mAuthority);
        }

        try {
            StringBuilder snList = new StringBuilder();

            for (BigInteger serialNumber : serialNumbers) {

                processor.addSerialNumberToUnrevoke(serialNumber);

                if (snList.length() > 0)
                    snList.append(", ");
                snList.append("0x");
                snList.append(serialNumber.toString(16));
            }

            header.addStringValue("serialNumber", snList.toString());

            processor.createUnrevocationRequest();

            processor.auditChangeRequest(ILogger.SUCCESS);

        } catch (EBaseException e) {
            processor.log(ILogger.LL_FAILURE, "Error " + e);
            processor.auditChangeRequest(ILogger.FAILURE);

            throw e;
        }

        // change audit processing from "REQUEST" to "REQUEST_PROCESSED"
        // to distinguish which type of signed audit log message to save
        // as a failure outcome in case an exception occurs

        try {
            processor.processUnrevocationRequest();
            IRequest unrevReq = processor.getRequest();

            RequestStatus status = unrevReq.getRequestStatus();
            String type = unrevReq.getRequestType();

            if (status == RequestStatus.COMPLETE
                    || status == RequestStatus.SVC_PENDING && type.equals(IRequest.CLA_UNCERT4CRL_REQUEST)) {

                Integer result = unrevReq.getExtDataInInteger(IRequest.RESULT);

                if (result != null && result.equals(IRequest.RES_SUCCESS)) {
                    header.addStringValue("unrevoked", "yes");

                } else {
                    header.addStringValue("unrevoked", "no");
                    String error = unrevReq.getExtDataInString(IRequest.ERROR);

                    if (error != null) {
                        header.addStringValue("error", error);

                        // TODO: throw exception on error?
                        // throw new EBaseException(error);
                    }
                }

                Integer updateCRLResult = unrevReq.getExtDataInInteger(IRequest.CRL_UPDATE_STATUS);

                if (updateCRLResult != null) {
                    header.addStringValue("updateCRL", "yes");

                    if (updateCRLResult.equals(IRequest.RES_SUCCESS)) {
                        header.addStringValue("updateCRLSuccess", "yes");

                    } else {
                        header.addStringValue("updateCRLSuccess", "no");
                        String crlError = unrevReq.getExtDataInString(IRequest.CRL_UPDATE_ERROR);

                        if (crlError != null)
                            header.addStringValue("updateCRLError", crlError);
                    }

                    // let known crl publishing status too.
                    Integer publishCRLResult = unrevReq.getExtDataInInteger(IRequest.CRL_PUBLISH_STATUS);

                    if (publishCRLResult != null) {
                        if (publishCRLResult.equals(IRequest.RES_SUCCESS)) {
                            header.addStringValue("publishCRLSuccess", "yes");

                        } else {
                            header.addStringValue("publishCRLSuccess", "no");
                            String publError = unrevReq.getExtDataInString(IRequest.CRL_PUBLISH_ERROR);

                            if (publError != null)
                                header.addStringValue("publishCRLError", publError);
                        }
                    }
                }

                // let known update and publish status of all crls.
                Enumeration<ICRLIssuingPoint> otherCRLs = ((ICertificateAuthority) mAuthority).getCRLIssuingPoints();

                while (otherCRLs.hasMoreElements()) {
                    ICRLIssuingPoint crl = otherCRLs.nextElement();
                    String crlId = crl.getId();

                    if (crlId.equals(ICertificateAuthority.PROP_MASTER_CRL))
                        continue;

                    String updateStatusStr = crl.getCrlUpdateStatusStr();
                    Integer updateResult = unrevReq.getExtDataInInteger(updateStatusStr);

                    if (updateResult != null) {
                        if (updateResult.equals(IRequest.RES_SUCCESS)) {
                            CMS.debug("DoUnrevoke: adding header " + updateStatusStr + " yes");
                            header.addStringValue(updateStatusStr, "yes");

                        } else {
                            String updateErrorStr = crl.getCrlUpdateErrorStr();

                            CMS.debug("DoUnrevoke: adding header " + updateStatusStr + " no");
                            header.addStringValue(updateStatusStr, "no");
                            String error = unrevReq.getExtDataInString(updateErrorStr);

                            if (error != null)
                                header.addStringValue(updateErrorStr, error);
                        }

                        String publishStatusStr = crl.getCrlPublishStatusStr();
                        Integer publishResult = unrevReq.getExtDataInInteger(publishStatusStr);

                        if (publishResult == null)
                            continue;

                        if (publishResult.equals(IRequest.RES_SUCCESS)) {
                            header.addStringValue(publishStatusStr, "yes");

                        } else {
                            String publishErrorStr = crl.getCrlPublishErrorStr();
                            header.addStringValue(publishStatusStr, "no");
                            String error = unrevReq.getExtDataInString(publishErrorStr);

                            if (error != null)
                                header.addStringValue(publishErrorStr, error);
                        }
                    }
                }

                if (mPublisherProcessor != null && mPublisherProcessor.ldapEnabled()) {
                    header.addStringValue("dirEnabled", "yes");
                    Integer[] ldapPublishStatus = unrevReq.getExtDataInIntegerArray("ldapPublishStatus");

                    if (ldapPublishStatus != null) {
                        if (ldapPublishStatus[0] == IRequest.RES_SUCCESS) {
                            header.addStringValue("dirUpdated", "yes");
                        } else {
                            header.addStringValue("dirUpdated", "no");
                        }
                    }
                } else {
                    header.addStringValue("dirEnabled", "no");
                }

            } else if (status == RequestStatus.PENDING) {
                header.addStringValue("error", "Request Pending");
                header.addStringValue("unrevoked", "pending");

            } else {
                header.addStringValue("error", "Request Status.Error");
                header.addStringValue("unrevoked", "no");
            }

            processor.auditChangeRequestProcessed(ILogger.SUCCESS);

        } catch (EBaseException e) {
            processor.log(ILogger.LL_FAILURE, "Error " + e);
            processor.auditChangeRequestProcessed(ILogger.FAILURE);

            throw e;
        }
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
    private RequestId auditRequesterID(HttpServletRequest req) {
        String requesterID = req.getParameter("requestId");

        if (requesterID != null) {
            return new RequestId(requesterID.trim());
        } else {
            return null;
        }
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
    private CertId auditSerialNumber(String eeSerialNumber) {
        if (eeSerialNumber != null) {
            return new CertId(eeSerialNumber.trim());
        } else {
            return null;
        }
    }
}
