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
package com.netscape.cms.servlet.request;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.extensions.NSCertTypeExtension;
import netscape.security.extensions.PresenceServerExtension;
import netscape.security.util.DerValue;
import netscape.security.x509.AlgorithmId;
import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateVersion;
import netscape.security.x509.Extension;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authority.ICertAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.IPublisherProcessor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.cert.ImportCertsTemplateFiller;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmsutil.util.Utils;

/**
 * Agent operations on Certificate requests. This servlet is used
 * by an Agent to approve, reject, reassign, or change a certificate
 * request.
 *
 * @version $Revision$, $Date$
 */
public class ProcessCertReq extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = 812464895240811318L;
    private final static String SEQNUM = "seqNum";
    private final static String TPL_FILE = "processCertReq.template";

    private IRequestQueue mQueue = null;
    private String mFormPath = null;
    private IReqParser mParser = null;
    private IPublisherProcessor mPublisherProcessor = null;
    private boolean mExtraAgentParams = false;

    // for RA only since it does not have a database.
    private final static String REQ_COMPLETED_TEMPLATE = "ra/RequestCompleted.template";
    private final static String PROP_REQ_COMPLETED_TEMPLATE = "requestCompletedTemplate";
    private final static String PROP_EXTRA_AGENT_PARAMS = "extraAgentParams";
    private String mReqCompletedTemplate = null;

    private String auditServiceID = ILogger.UNIDENTIFIED;
    private final static String AGENT_CA_CLONE_ENROLLMENT_SERVLET =
            "caProcessCertReq";
    private final static String AGENT_RA_CLONE_ENROLLMENT_SERVLET =
            "raProcessCertReq";
    private final static String SIGNED_AUDIT_ACCEPTANCE = "accept";
    private final static String SIGNED_AUDIT_CANCELLATION = "cancel";
    private final static String SIGNED_AUDIT_CLONING = "clone";
    private final static String SIGNED_AUDIT_REJECTION = "reject";
    private final static byte EOL[] = { Character.LINE_SEPARATOR };
    private final static String[] SIGNED_AUDIT_MANUAL_CANCELLATION_REASON = new String[] {

    /* 0 */"manual non-profile cert request cancellation:  "
            + "request cannot be processed due to an "
            + "authorization failure",

    /* 1 */"manual non-profile cert request cancellation:  "
            + "no reason has been given for cancelling this "
            + "cert request",

    /* 2 */"manual non-profile cert request cancellation:  "
            + "indeterminate reason for inability to process "
            + "cert request due to an EBaseException",

    /* 3 */"manual non-profile cert request cancellation:  "
            + "indeterminate reason for inability to process "
            + "cert request due to an IOException",

    /* 4 */"manual non-profile cert request cancellation:  "
            + "indeterminate reason for inability to process "
            + "cert request due to a CertificateException",

    /* 5 */"manual non-profile cert request cancellation:  "
            + "indeterminate reason for inability to process "
            + "cert request due to a NoSuchAlgorithmException"
        };
    private final static String[] SIGNED_AUDIT_MANUAL_REJECTION_REASON = new String[] {

    /* 0 */"manual non-profile cert request rejection:  "
            + "request cannot be processed due to an "
            + "authorization failure",

    /* 1 */"manual non-profile cert request rejection:  "
            + "no reason has been given for rejecting this "
            + "cert request",

    /* 2 */"manual non-profile cert request rejection:  "
            + "indeterminate reason for inability to process "
            + "cert request due to an EBaseException",

    /* 3 */"manual non-profile cert request rejection:  "
            + "indeterminate reason for inability to process "
            + "cert request due to an IOException",

    /* 4 */"manual non-profile cert request rejection:  "
            + "indeterminate reason for inability to process "
            + "cert request due to a CertificateException",

    /* 5 */"manual non-profile cert request rejection:  "
            + "indeterminate reason for inability to process "
            + "cert request due to a NoSuchAlgorithmException"
        };
    private final static String LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST =
            "LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST_5";
    private final static String LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED_5";

    /**
     * Process request.
     */
    public ProcessCertReq()
            throws EBaseException {
        super();
    }

    /**
     * initialize the servlet. This servlet uses the template file
     * "processCertReq.template" to process the response.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        try {
            super.init(sc);

            // determine the service ID for signed audit log messages
            String id = sc.getInitParameter(CMSServlet.PROP_ID);

            if (id != null) {
                if (!(auditServiceID.equals(
                            AGENT_CA_CLONE_ENROLLMENT_SERVLET))
                        && !(auditServiceID.equals(
                                AGENT_RA_CLONE_ENROLLMENT_SERVLET))) {
                    auditServiceID = ILogger.UNIDENTIFIED;
                } else {
                    auditServiceID = id.trim();
                }
            }

            mQueue = mAuthority.getRequestQueue();
            mPublisherProcessor =
                    ((ICertAuthority) mAuthority).getPublisherProcessor();

            mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

            mParser = CertReqParser.DETAIL_PARSER;

            // override success and error templates to null -
            // handle templates locally.
            mTemplates.remove(ICMSRequest.SUCCESS);

            try {
                mReqCompletedTemplate = sc.getInitParameter(
                            PROP_REQ_COMPLETED_TEMPLATE);
                if (mReqCompletedTemplate == null)
                    mReqCompletedTemplate = REQ_COMPLETED_TEMPLATE;
                String tmp = sc.getInitParameter(PROP_EXTRA_AGENT_PARAMS);

                if (tmp != null && tmp.trim().equalsIgnoreCase("true"))
                    mExtraAgentParams = true;
                else
                    mExtraAgentParams = false;
            } catch (Exception e) {
                // does not happen.
            }
        } catch (ServletException eAudit1) {
            // rethrow caught exception
            throw eAudit1;
        }
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param seqNum request id
     * <li>http.param notValidBefore certificate validity - notBefore - in seconds since jan 1, 1970
     * <li>http.param notValidAfter certificate validity - notAfter - in seconds since jan 1, 1970
     * <li>http.param subject certificate subject name
     * <li>http.param toDo requested action (can be one of: clone, reject, accept, cancel)
     * <li>http.param signatureAlgorithm certificate signing algorithm
     * <li>http.param addExts base-64, DER encoded Extension or SEQUENCE OF Extensions to add to certificate
     * <li>http.param pathLenConstraint integer path length constraint to use in BasicConstraint extension if applicable
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        long startTime = CMS.getCurrentDate().getTime();
        String toDo = null;
        String subject = null;
        String signatureAlgorithm = null;
        long notValidBefore = 0;
        long notValidAfter = 0;
        BigInteger seqNum = BigInteger.ONE.negate();
        EBaseException error = null;

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        try {
            if (req.getParameter(SEQNUM) != null) {
                CMS.debug(
                        "ProcessCertReq: parameter seqNum " + req.getParameter(SEQNUM));
                seqNum = new BigInteger(req.getParameter(SEQNUM));
            }
            String notValidBeforeStr = req.getParameter("notValidBefore");

            if (notValidBeforeStr != null && notValidBeforeStr.length() > 0) {
                notValidBefore = Long.parseLong(notValidBeforeStr);
                notValidBefore *= 1000;
            }
            String notValidAfterStr = req.getParameter("notValidAfter");

            if (notValidAfterStr != null && notValidAfterStr.length() > 0) {
                notValidAfter = Long.parseLong(notValidAfterStr);
                notValidAfter *= 1000;
            }

            toDo = req.getParameter("toDo");

            subject = req.getParameter("subject");
            signatureAlgorithm = req.getParameter("signatureAlgorithm");

            IRequest r = null;

            if (seqNum.compareTo(BigInteger.ONE.negate()) > 0) {
                r = mQueue.findRequest(new RequestId(seqNum));
            }

            if (seqNum.compareTo(BigInteger.ONE.negate()) > 0 && r != null) {
                processX509(cmsReq, argSet, header, seqNum, req, resp,
                        toDo, signatureAlgorithm, subject,
                        notValidBefore, notValidAfter, locale[0], startTime);
            } else {
                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_INVALID_REQUEST_ID_1", seqNum.toString()));
                error = new ECMSGWException(
                        CMS.getUserMessage("CMS_GW_INVALID_REQUEST_ID",
                                seqNum.toString()));
            }
        } catch (EBaseException e) {
            error = e;
        } catch (NumberFormatException e) {
            log(ILogger.LL_FAILURE, "Error " + e);
            error = new EBaseException(CMS.getUserMessage(getLocale(req), "CMS_BASE_INVALID_NUMBER_FORMAT"));
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
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
        return;
    }

    /**
     * Process X509 certificate enrollment request and send request information
     * to the caller.
     * <P>
     *
     * (Certificate Request - an "agent" cert request for "cloning")
     * <P>
     *
     * (Certificate Request Processed - either a manual "agent" non-profile based cert acceptance, a manual "agent"
     * non-profile based cert cancellation, or a manual "agent" non-profile based cert rejection)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST used when a non-profile cert request is made
     * (before approval process)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a certificate request has just been
     * through the approval process
     * </ul>
     *
     * @param cmsReq a certificate enrollment request
     * @param argSet CMS template parameters
     * @param header argument block
     * @param seqNum sequence number
     * @param req HTTP servlet request
     * @param resp HTTP servlet response
     * @param toDo string representing the requested action (can be one of:
     *            clone, reject, accept, cancel)
     * @param signatureAlgorithm string containing the signature algorithm
     * @param subject string containing the subject name of the certificate
     * @param notValidBefore certificate validity - notBefore - in seconds
     *            since Jan 1, 1970
     * @param notValidAfter certificate validity - notAfter - in seconds since
     *            Jan 1, 1970
     * @param locale the system locale
     * @param startTime the current date
     * @exception EBaseException an error has occurred
     */
    private void processX509(CMSRequest cmsReq,
            CMSTemplateParams argSet, IArgBlock header,
            BigInteger seqNum, HttpServletRequest req,
            HttpServletResponse resp,
            String toDo, String signatureAlgorithm,
            String subject,
            long notValidBefore, long notValidAfter,
            Locale locale, long startTime)
            throws EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditRequesterID = ILogger.UNIDENTIFIED;
        String auditCertificateSubjectName = subject;
        String auditInfoName = auditInfoName(toDo);
        String id = null;

        // "normalize" the "auditCertificateSubjectName"
        if (auditCertificateSubjectName != null) {
            // NOTE:  This is ok even if the cert subject name is "" (empty)!
            auditCertificateSubjectName = auditCertificateSubjectName.trim();
        } else {
            // NOTE:  Here, the cert subject name is MISSING, not "" (empty)!
            auditCertificateSubjectName = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        try {
            IRequest r = mQueue.findRequest(new RequestId(seqNum));

            if (r != null) {
                // overwrite "auditRequesterID" if and only if "id" != null
                id = r.getRequestId().toString();
                if (id != null) {
                    auditRequesterID = id.trim();
                }
            }

            if (mAuthority != null)
                header.addStringValue("authorityid", mAuthority.getId());

            if (toDo != null) {
                // for audit log
                IAuthToken authToken = authenticate(cmsReq);
                AuthzToken authzToken = null;

                try {
                    authzToken = authorize(mAclMethod, authToken,
                                mAuthzResourceName, "execute");
                } catch (EAuthzAccessDenied e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE",
                                    e.toString()));
                } catch (Exception e) {
                    log(ILogger.LL_FAILURE,
                            CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE",
                                    e.toString()));
                }

                if (authzToken == null) {
                    cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);

                    // store a message in the signed audit log file
                    if (toDo.equals(SIGNED_AUDIT_CLONING)) {
                        // ("agent" cert request for "cloning")
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    auditServiceID,
                                    auditCertificateSubjectName);

                        audit(auditMessage);
                    } else if (toDo.equals(SIGNED_AUDIT_ACCEPTANCE)) {
                        // (manual "agent" cert request processed - "accepted")
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    auditInfoName,
                                    ILogger.SIGNED_AUDIT_EMPTY_VALUE);

                        audit(auditMessage);
                    } else if (toDo.equals(SIGNED_AUDIT_CANCELLATION)) {
                        // (manual "agent" cert request processed - "cancelled")
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    auditInfoName,
                                    SIGNED_AUDIT_MANUAL_CANCELLATION_REASON[0]);

                        audit(auditMessage);
                    } else if (toDo.equals(SIGNED_AUDIT_REJECTION)) {
                        // (manual "agent" cert request processed - "rejected")
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    auditInfoName,
                                    SIGNED_AUDIT_MANUAL_REJECTION_REASON[0]);

                        audit(auditMessage);
                    }

                    return;
                }

                String authMgr = AuditFormat.NOAUTH;

                if (authToken != null) {
                    authMgr =
                            authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
                }
                String agentID = authToken.getInString("userid");
                String initiative = AuditFormat.FROMAGENT + " agentID: " + agentID;

                // Get the certificate info from the request
                X509CertInfo certInfo[] = r.getExtDataInCertInfoArray(IRequest.CERT_INFO);

                header.addStringValue("toDo", toDo);
                if (toDo.equals("accept")) {

                    if (certInfo != null) {
                        int alterationCounter = 0;

                        for (int i = 0; i < certInfo.length; i++) {
                            CertificateAlgorithmId certAlgId =
                                    (CertificateAlgorithmId)
                                    certInfo[i].get(X509CertInfo.ALGORITHM_ID);

                            AlgorithmId algId = (AlgorithmId)
                                    certAlgId.get(CertificateAlgorithmId.ALGORITHM);

                            if (!(algId.getName().equals(signatureAlgorithm))) {
                                alterationCounter++;
                                AlgorithmId newAlgId = AlgorithmId.get(signatureAlgorithm);

                                certInfo[i].set(X509CertInfo.ALGORITHM_ID,
                                        new CertificateAlgorithmId(newAlgId));
                            }

                            CertificateSubjectName certSubject =
                                    (CertificateSubjectName)
                                    certInfo[i].get(X509CertInfo.SUBJECT);

                            if (subject != null &&
                                    !(certSubject.toString().equals(subject))) {

                                alterationCounter++;
                                certInfo[i].set(X509CertInfo.SUBJECT,
                                        new CertificateSubjectName(
                                                (new X500Name(subject))));
                            }

                            CertificateValidity certValidity =
                                    (CertificateValidity)
                                    certInfo[i].get(X509CertInfo.VALIDITY);
                            Date currentTime = CMS.getCurrentDate();
                            boolean validityChanged = false;

                            // only override these values if agent specified them
                            if (notValidBefore > 0) {
                                Date notBefore = (Date) certValidity.get(
                                        CertificateValidity.NOT_BEFORE);

                                if (notBefore.getTime() == 0 ||
                                        notBefore.getTime() != notValidBefore) {
                                    Date validFrom = new Date(notValidBefore);

                                    notBefore = (notValidBefore == 0) ? currentTime : validFrom;
                                    certValidity.set(CertificateValidity.NOT_BEFORE,
                                            notBefore);
                                    validityChanged = true;
                                }
                            }
                            if (notValidAfter > 0) {
                                Date validTo = new Date(notValidAfter);
                                Date notAfter = (Date)
                                        certValidity.get(CertificateValidity.NOT_AFTER);

                                if (notAfter.getTime() == 0 ||
                                        notAfter.getTime() != notValidAfter) {
                                    notAfter = currentTime;
                                    notAfter = (notValidAfter == 0) ? currentTime : validTo;
                                    certValidity.set(CertificateValidity.NOT_AFTER,
                                            notAfter);
                                    validityChanged = true;
                                }
                            }
                            if (validityChanged) {
                                // this set() trigger this rebuild of internal
                                // raw der encoding cache of X509CertInfo.
                                // Otherwise, the above change wont have effect.
                                certInfo[i].set(X509CertInfo.VALIDITY, certValidity);
                            }

                            if (certInfo[i].get(X509CertInfo.VERSION) == null) {
                                certInfo[i].set(X509CertInfo.VERSION,
                                        new CertificateVersion(
                                                CertificateVersion.V3));
                            }

                            CertificateExtensions extensions = null;

                            try {
                                extensions = (CertificateExtensions)
                                        certInfo[i].get(X509CertInfo.EXTENSIONS);
                            } catch (Exception e) {
                                log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERROR_PARSING_EXTENS", e.toString()));
                            }

                            // 99/08/31 #361906 - handling additional extensions
                            String addExts = req.getParameter("addExts");

                            if (addExts != null && !addExts.trim().equals("")) {
                                Vector<Extension> extsToBeAdded = new Vector<Extension>();

                                byte[] b = Utils.base64decode(addExts);

                                // this b can be "Extension" Or "SEQUENCE OF Extension"
                                try {
                                    DerValue b_der = new DerValue(b);

                                    while (b_der.data.available() != 0) {
                                        Extension de = new Extension(b_der.data.getDerValue());

                                        extsToBeAdded.addElement(de);
                                    }
                                } catch (IOException e) {
                                    // it could be a single extension
                                    Extension de = new Extension(new DerValue(b));

                                    extsToBeAdded.addElement(de);
                                }
                                if (extsToBeAdded.size() > 0) {
                                    if (extensions == null) {
                                        extensions = new CertificateExtensions();
                                        certInfo[i].set(X509CertInfo.EXTENSIONS, extensions);
                                    }
                                    for (int j = 0; j < extsToBeAdded.size(); j++) {
                                        Extension theExt = extsToBeAdded.elementAt(j);

                                        extensions.set(theExt.getExtensionId().toString(), theExt);
                                    }
                                }
                            }

                            if (extensions != null) {
                                try {
                                    NSCertTypeExtension nsExtensions =
                                            (NSCertTypeExtension)
                                            extensions.get(
                                                    NSCertTypeExtension.NAME);

                                    if (nsExtensions != null) {
                                        updateNSExtension(req, nsExtensions);
                                    }
                                } catch (IOException e) {
                                    log(ILogger.LL_FAILURE,
                                            CMS.getLogMessage("CMSGW_ERROR_PROCESS_NETSCAPE_EXTENSION", e.toString()));
                                }

                                String pathLength = req.getParameter("pathLenConstraint");

                                if (pathLength != null) {
                                    try {
                                        int pathLen = Integer.parseInt(pathLength);
                                        BasicConstraintsExtension bcExt =
                                                (BasicConstraintsExtension)
                                                extensions.get(
                                                        BasicConstraintsExtension.NAME);

                                        if (bcExt != null) {
                                            Integer bcPathLen = (Integer) bcExt.get(BasicConstraintsExtension.PATH_LEN);
                                            Boolean isCA = (Boolean) bcExt.get(BasicConstraintsExtension.IS_CA);

                                            if (bcPathLen != null &&
                                                    bcPathLen.intValue() != pathLen &&
                                                    isCA != null) {
                                                BasicConstraintsExtension bcExt0 =
                                                        new BasicConstraintsExtension(isCA.booleanValue(), pathLen);

                                                extensions.delete(BasicConstraintsExtension.NAME);
                                                extensions.set(BasicConstraintsExtension.NAME, bcExt0);
                                                alterationCounter++;
                                            }
                                        }
                                    } catch (IOException e) {
                                        log(ILogger.LL_FAILURE,
                                                CMS.getLogMessage("CMSGW_ERROR_PROCESS_CONSTRAINTS_EXTENSION",
                                                        e.toString()));
                                    } catch (NumberFormatException e) {
                                        log(ILogger.LL_FAILURE,
                                                CMS.getLogMessage("CMSGW_ERROR_PROCESS_CONSTRAINTS_EXTENSION",
                                                        e.toString()));
                                    }
                                }

                                // handle Presence Server Extension
                                String PSE_Enable = req.getParameter("PSE_Enable");

                                if (PSE_Enable != null) {
                                    boolean Critical = (req.getParameter("PSE_Critical") != null);
                                    int Version = 0;

                                    try {
                                        Version = Integer.parseInt(req.getParameter("PSE_Version"));
                                    } catch (Exception e1) {
                                    }
                                    String StreetAddress = req.getParameter("PSE_StreetAddress");

                                    if (StreetAddress == null) {
                                        StreetAddress = "";
                                    }
                                    String TelephoneNumber = req.getParameter("PSE_TelephoneNumber");

                                    if (TelephoneNumber == null) {
                                        TelephoneNumber = "";
                                    }
                                    String RFC822Name = req.getParameter("PSE_RFC822Name");

                                    if (RFC822Name == null) {
                                        RFC822Name = "";
                                    }
                                    String IMID = req.getParameter("PSE_IMID");

                                    if (IMID == null) {
                                        IMID = "";
                                    }
                                    String HostName = req.getParameter("PSE_HostName");

                                    if (HostName == null) {
                                        HostName = "";
                                    }
                                    int PortNumber = 0;

                                    try {
                                        PortNumber = Integer.parseInt(req.getParameter("PSE_PortNumber"));
                                    } catch (Exception e1) {
                                    }
                                    int MaxUsers = 0;

                                    try {
                                        MaxUsers = Integer.parseInt(req.getParameter("PSE_MaxUsers"));
                                    } catch (Exception e1) {
                                    }
                                    int ServiceLevel = 0;

                                    try {
                                        ServiceLevel = Integer.parseInt(req.getParameter("PSE_ServiceLevel"));
                                    } catch (Exception e1) {
                                    }
                                    // create extension
                                    PresenceServerExtension pseExt =
                                            new PresenceServerExtension(Critical, Version, StreetAddress,
                                                    TelephoneNumber, RFC822Name, IMID, HostName, PortNumber, MaxUsers,
                                                    ServiceLevel);

                                    extensions.set(pseExt.getExtensionId().toString(), pseExt);
                                }

                                if (mExtraAgentParams) {
                                    Enumeration<String> extraparams = req.getParameterNames();
                                    int l = IRequest.AGENT_PARAMS.length() + 1;
                                    int ap_counter = 0;
                                    Hashtable<String, String> agentparamsargblock = new Hashtable<String, String>();

                                    if (extraparams != null) {
                                        while (extraparams.hasMoreElements()) {
                                            String s = extraparams.nextElement();

                                            if (s.startsWith(IRequest.AGENT_PARAMS)) {
                                                String param_value = req.getParameter(s);

                                                if (param_value != null) {
                                                    String new_name = s.substring(l);

                                                    agentparamsargblock.put(new_name, param_value);
                                                    ap_counter += 1;
                                                }
                                            }
                                        }
                                    }
                                    if (ap_counter > 0) {
                                        r.setExtData(IRequest.AGENT_PARAMS, agentparamsargblock);
                                        alterationCounter++;
                                    }
                                }

                                // this set() trigger this rebuild of internal
                                // raw der encoding cache of X509CertInfo.
                                // Otherwise, the above change wont have effect.
                                certInfo[i].set(X509CertInfo.EXTENSIONS, extensions);
                            }
                            alterationCounter += updateExtensionsInRequest(req, r);
                        }
                        if (alterationCounter > 0) {
                            mQueue.updateRequest(r);
                        }
                    }

                    mQueue.approveRequest(r);

                    if (r.getRequestStatus().equals(RequestStatus.PENDING)) {
                        cmsReq.setResult(r);
                        cmsReq.setStatus(ICMSRequest.PENDING);
                        if (certInfo != null) {
                            for (int i = 0; i < certInfo.length; i++) {
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.FORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                "pending",
                                                certInfo[i].get(X509CertInfo.SUBJECT),
                                                "" }
                                        );
                            }
                        } else {
                            if (subject != null) {
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.FORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                "pending",
                                                subject,
                                                "" }
                                        );
                            } else {
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.NODNFORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                "pending" }
                                        );
                            }
                        }
                    } else if (r.getRequestStatus().equals(
                            RequestStatus.APPROVED) ||
                            r.getRequestStatus().equals(
                                    RequestStatus.SVC_PENDING)) {
                        cmsReq.setResult(r);
                        cmsReq.setStatus(ICMSRequest.SVC_PENDING);
                        if (certInfo != null) {
                            for (int i = 0; i < certInfo.length; i++) {
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.FORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                r.getRequestStatus(),
                                                certInfo[i].get(X509CertInfo.SUBJECT),
                                                "" }
                                        );
                            }
                        } else {
                            if (subject != null) {
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.FORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                r.getRequestStatus(),
                                                subject,
                                                "" }
                                        );
                            } else {
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.NODNFORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                r.getRequestStatus() }
                                        );
                            }
                        }
                    } else if (r.getRequestStatus().equals(
                            RequestStatus.COMPLETE)) {
                        cmsReq.setStatus(ICMSRequest.SUCCESS);

                        // XXX make the repeat record.
                        // Get the certificate(s) from the request
                        X509CertImpl issuedCerts[] =
                                r.getExtDataInCertArray(IRequest.ISSUED_CERTS);

                        // return potentially more than one certificates.
                        if (issuedCerts != null) {
                            long endTime = CMS.getCurrentDate().getTime();
                            StringBuffer sbuf = new StringBuffer();

                            //header.addBigIntegerValue("serialNumber",
                            //issuedCerts[0].getSerialNumber(),16);
                            for (int i = 0; i < issuedCerts.length; i++) {
                                if (i != 0)
                                    sbuf.append(", ");
                                sbuf.append("0x" +
                                        issuedCerts[i].getSerialNumber().toString(16));
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.FORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                "completed",
                                                issuedCerts[i].getSubjectDN(),
                                                "cert issued serial number: 0x"
                                                        +
                                                        issuedCerts[i].getSerialNumber().toString(16) + " time: "
                                                        + (endTime - startTime) }
                                        );

                                // store a message in the signed audit log file
                                // (one for each manual "agent"
                                //  cert request processed - "accepted")
                                auditMessage = CMS.getLogMessage(
                                            LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                            auditSubjectID,
                                            ILogger.SUCCESS,
                                            auditRequesterID,
                                            auditInfoName,
                                            auditInfoCertValue(issuedCerts[i]));

                                audit(auditMessage);
                            }
                            header.addStringValue(
                                    "serialNumber", sbuf.toString());
                        } else {
                            if (subject != null) {
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.FORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                "completed",
                                                subject,
                                                "" }
                                        );
                            } else {
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.NODNFORMAT,
                                        new Object[] {
                                                r.getRequestType(),
                                                r.getRequestId(),
                                                initiative,
                                                authMgr,
                                                "completed" }
                                        );
                            }

                            // store a message in the signed audit log file
                            // (manual "agent" cert request processed
                            //  - "accepted")
                            auditMessage = CMS.getLogMessage(
                                        LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                        auditSubjectID,
                                        ILogger.SUCCESS,
                                        auditRequesterID,
                                        auditInfoName,
                                        ILogger.SIGNED_AUDIT_EMPTY_VALUE);

                            audit(auditMessage);
                        }

                        // grant trusted manager or agent privileges
                        try {
                            int res = grant_privileges(
                                    cmsReq, r, issuedCerts, header);

                            if (res != 0) {
                                header.addStringValue(GRANT_ERROR, "SUCCESS");
                            }
                        } catch (EBaseException e) {
                            header.addStringValue(GRANT_ERROR, e.toString());
                        }

                        // if this is a RA, show the certificate right away
                        // since ther is no cert database.
                        /*
                         if (mAuthority instanceof RegistrationAuthority) {
                         Object[] results =
                         new Object[] { issuedCerts, grantError };
                         cmsReq.setResult(results);
                         renderTemplate(cmsReq,
                         mReqCompletedTemplate, REQ_COMPLETED_FILLER);

                         return;
                         }
                         */

                        cmsReq.setResult(r);

                        String scheme = req.getScheme();

                        if (scheme.equals("http") &&
                                connectionIsSSL(req))
                            scheme = "https";

                        /*
                         header.addStringValue(
                         "authorityid", mAuthority.getId());
                         header.addStringValue("serviceURL", scheme +"://"+
                         req.getServerName() + ":"+
                         req.getServerPort() +
                         req.getRequestURI());
                         */

                        if (mPublisherProcessor != null && mPublisherProcessor.ldapEnabled()) {
                            header.addStringValue("dirEnabled", "yes");

                            Integer[] ldapPublishStatus =
                                    r.getExtDataInIntegerArray("ldapPublishStatus");
                            int certsUpdated = 0;

                            if (ldapPublishStatus != null) {
                                for (int i = 0; i < ldapPublishStatus.length; i++) {
                                    if (ldapPublishStatus[i] == IRequest.RES_SUCCESS) {
                                        certsUpdated++;
                                    }
                                }
                            }
                            header.addIntegerValue("certsUpdated", certsUpdated);

                        } else {
                            header.addStringValue("dirEnabled", "no");
                        }
                    }

                } else if (toDo.equals("reject")) {
                    mQueue.rejectRequest(r);
                    if (certInfo != null) {
                        for (int i = 0; i < certInfo.length; i++) {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.FORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "rejected",
                                            certInfo[i].get(X509CertInfo.SUBJECT),
                                            "" }
                                    );
                        }
                    } else {
                        if (subject != null) {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.FORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "rejected",
                                            subject,
                                            "" }
                                    );
                        } else {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.NODNFORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "rejected" }
                                    );
                        }
                    }

                    // store a message in the signed audit log file
                    // (manual "agent" cert request processed - "rejected")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.SUCCESS,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_REJECTION_REASON[1]);

                    audit(auditMessage);

                } else if (toDo.equals("cancel")) {
                    mQueue.cancelRequest(r);

                    if (certInfo != null) {
                        for (int i = 0; i < certInfo.length; i++) {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.FORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "canceled",
                                            certInfo[i].get(X509CertInfo.SUBJECT),
                                            "" }
                                    );
                        }
                    } else {
                        if (subject != null) {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.FORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "canceled",
                                            subject,
                                            "" }
                                    );
                        } else {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.NODNFORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "canceled" }
                                    );
                        }

                    }

                    // store a message in the signed audit log file
                    // (manual "agent" cert request processed - "cancelled")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.SUCCESS,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_CANCELLATION_REASON[1]);

                    audit(auditMessage);

                } else if (toDo.equals("clone")) {
                    IRequest clonedRequest = mQueue.cloneAndMarkPending(r);

                    header.addStringValue("clonedRequestId",
                            clonedRequest.getRequestId().toString());

                    if (certInfo != null) {
                        for (int i = 0; i < certInfo.length; i++) {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.FORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "cloned to reqID: " +
                                                    clonedRequest.getRequestId().toString(),
                                            certInfo[i].get(X509CertInfo.SUBJECT),
                                            "" }
                                    );
                        }
                    } else {
                        if (subject != null) {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.FORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "cloned to reqID: " +
                                                    clonedRequest.getRequestId().toString(),
                                            subject,
                                            "" }
                                    );
                        } else {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.NODNFORMAT,
                                    new Object[] {
                                            r.getRequestType(),
                                            r.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "cloned to reqID: " +
                                                    clonedRequest.getRequestId().toString() }
                                    );
                        }
                    }

                    // store a message in the signed audit log file
                    // ("agent" cert request for "cloning")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST,
                                auditSubjectID,
                                ILogger.SUCCESS,
                                auditRequesterID,
                                auditServiceID,
                                auditCertificateSubjectName);

                    audit(auditMessage);
                }
            }

            // add authority names to know what privileges can be requested.
            if (CMS.getSubsystem("kra") != null)
                header.addStringValue("localkra", "yes");
            if (CMS.getSubsystem("ca") != null)
                header.addStringValue("localca", "yes");
            if (CMS.getSubsystem("ra") != null)
                header.addStringValue("localra", "yes");

            header.addBigIntegerValue("seqNum", seqNum, 10);
            mParser.fillRequestIntoArg(locale, r, argSet, header);
            String rid = r.getExtDataInString(IRequest.REMOTE_REQID);

            if (rid != null)
                header.addStringValue("remoteReqID", rid);
        } catch (EBaseException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));

            // store a message in the signed audit log file
            if (toDo != null) {
                if (toDo.equals(SIGNED_AUDIT_CLONING)) {
                    // ("agent" cert request for "cloning")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditServiceID,
                                auditCertificateSubjectName);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_ACCEPTANCE)) {
                    // (manual "agent" cert request processed - "accepted")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                ILogger.SIGNED_AUDIT_EMPTY_VALUE);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_CANCELLATION)) {
                    // (manual "agent" cert request processed - "cancelled")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_CANCELLATION_REASON[2]);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_REJECTION)) {
                    // (manual "agent" cert request processed - "rejected")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_REJECTION_REASON[2]);

                    audit(auditMessage);
                }
            }

            throw e;
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));

            // store a message in the signed audit log file
            if (toDo != null) {
                if (toDo.equals(SIGNED_AUDIT_CLONING)) {
                    // ("agent" cert request for "cloning")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditServiceID,
                                auditCertificateSubjectName);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_ACCEPTANCE)) {
                    // (manual "agent" cert request processed - "accepted")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                ILogger.SIGNED_AUDIT_EMPTY_VALUE);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_CANCELLATION)) {
                    // (manual "agent" cert request processed - "cancelled")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_CANCELLATION_REASON[3]);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_REJECTION)) {
                    // (manual "agent" cert request processed - "rejected")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_REJECTION_REASON[3]);

                    audit(auditMessage);
                }
            }

            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_ENCODING_ISSUED_CERT_ERROR"));
        } catch (CertificateException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));

            // store a message in the signed audit log file
            if (toDo != null) {
                if (toDo.equals(SIGNED_AUDIT_CLONING)) {
                    // ("agent" cert request for "cloning")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditServiceID,
                                auditCertificateSubjectName);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_ACCEPTANCE)) {
                    // (manual "agent" cert request processed - "accepted")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                ILogger.SIGNED_AUDIT_EMPTY_VALUE);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_CANCELLATION)) {
                    // (manual "agent" cert request processed - "cancelled")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_CANCELLATION_REASON[4]);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_REJECTION)) {
                    // (manual "agent" cert request processed - "rejected")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_REJECTION_REASON[4]);

                    audit(auditMessage);
                }
            }

            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_ENCODING_ISSUED_CERT_ERROR"));
        } catch (NoSuchAlgorithmException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));

            // store a message in the signed audit log file
            if (toDo != null) {
                if (toDo.equals(SIGNED_AUDIT_CLONING)) {
                    // ("agent" cert request for "cloning")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_NON_PROFILE_CERT_REQUEST,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditServiceID,
                                auditCertificateSubjectName);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_ACCEPTANCE)) {
                    // (manual "agent" cert request processed - "accepted")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                ILogger.SIGNED_AUDIT_EMPTY_VALUE);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_CANCELLATION)) {
                    // (manual "agent" cert request processed - "cancelled")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_CANCELLATION_REASON[5]);

                    audit(auditMessage);
                } else if (toDo.equals(SIGNED_AUDIT_REJECTION)) {
                    // (manual "agent" cert request processed - "rejected")
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditRequesterID,
                                auditInfoName,
                                SIGNED_AUDIT_MANUAL_REJECTION_REASON[5]);

                    audit(auditMessage);
                }
            }

            throw new EBaseException(CMS.getUserMessage(locale, "CMS_BASE_INTERNAL_ERROR", e.toString()));
        }
        return;
    }

    private void updateNSExtension(HttpServletRequest req,
            NSCertTypeExtension ext) throws IOException {
        try {

            if (req.getParameter("certTypeSSLServer") == null) {
                ext.set(NSCertTypeExtension.SSL_SERVER, Boolean.valueOf(false));
            } else {
                ext.set(NSCertTypeExtension.SSL_SERVER, Boolean.valueOf(true));
            }

            if (req.getParameter("certTypeSSLClient") == null) {
                ext.set(NSCertTypeExtension.SSL_CLIENT, Boolean.valueOf(false));
            } else {
                ext.set(NSCertTypeExtension.SSL_CLIENT, Boolean.valueOf(true));
            }

            if (req.getParameter("certTypeEmail") == null) {
                ext.set(NSCertTypeExtension.EMAIL, Boolean.valueOf(false));
            } else {
                ext.set(NSCertTypeExtension.EMAIL, Boolean.valueOf(true));
            }

            if (req.getParameter("certTypeObjSigning") == null) {
                ext.set(NSCertTypeExtension.OBJECT_SIGNING, Boolean.valueOf(false));
            } else {
                ext.set(NSCertTypeExtension.OBJECT_SIGNING, Boolean.valueOf(true));
            }

            if (req.getParameter("certTypeEmailCA") == null) {
                ext.set(NSCertTypeExtension.EMAIL_CA, Boolean.valueOf(false));
            } else {
                ext.set(NSCertTypeExtension.EMAIL_CA, Boolean.valueOf(true));
            }

            if (req.getParameter("certTypeSSLCA") == null) {
                ext.set(NSCertTypeExtension.SSL_CA, Boolean.valueOf(false));
            } else {
                ext.set(NSCertTypeExtension.SSL_CA, Boolean.valueOf(true));
            }

            if (req.getParameter("certTypeObjSigningCA") == null) {
                ext.set(NSCertTypeExtension.OBJECT_SIGNING_CA, Boolean.valueOf(false));
            } else {
                ext.set(NSCertTypeExtension.OBJECT_SIGNING_CA, Boolean.valueOf(true));
            }
        } catch (CertificateException e) {
        }
    }

    /**
     * This method sets extensions parameter into the request so
     * that the NSCertTypeExtension policy creates new
     * NSCertTypExtension with this setting. Note that this
     * setting will not be used if the NSCertType Extension
     * already exist in CertificateExtension. In that case,
     * updateExtensions() will be called to set the extension
     * parameter into the extension directly.
     */
    private int updateExtensionsInRequest(HttpServletRequest req, IRequest r) {
        int nChanges = 0;

        if (req.getParameter("certTypeSSLServer") != null) {
            r.setExtData(NSCertTypeExtension.SSL_SERVER, "true");
            nChanges++;
        } else {
            r.deleteExtData(NSCertTypeExtension.SSL_SERVER);
            nChanges++;
        }

        if (req.getParameter("certTypeSSLClient") != null) {
            r.setExtData(NSCertTypeExtension.SSL_CLIENT, "true");
            nChanges++;
        } else {
            r.deleteExtData(NSCertTypeExtension.SSL_CLIENT);
            nChanges++;
        }

        if (req.getParameter("certTypeEmail") != null) {
            r.setExtData(NSCertTypeExtension.EMAIL, "true");
            nChanges++;
        } else {
            r.deleteExtData(NSCertTypeExtension.EMAIL);
            nChanges++;
        }

        if (req.getParameter("certTypeObjSigning") != null) {
            r.setExtData(NSCertTypeExtension.OBJECT_SIGNING, "true");
            nChanges++;
        } else {
            r.deleteExtData(NSCertTypeExtension.OBJECT_SIGNING);
            nChanges++;
        }

        if (req.getParameter("certTypeEmailCA") != null) {
            r.setExtData(NSCertTypeExtension.EMAIL_CA, "true");
            nChanges++;
        } else {
            r.deleteExtData(NSCertTypeExtension.EMAIL_CA);
            nChanges++;
        }

        if (req.getParameter("certTypeSSLCA") != null) {
            r.setExtData(NSCertTypeExtension.SSL_CA, "true");
            nChanges++;
        } else {
            r.deleteExtData(NSCertTypeExtension.SSL_CA);
            nChanges++;
        }

        if (req.getParameter("certTypeObjSigningCA") != null) {
            r.setExtData(NSCertTypeExtension.OBJECT_SIGNING_CA, "true");
            nChanges++;
        } else {
            r.deleteExtData(NSCertTypeExtension.OBJECT_SIGNING_CA);
            nChanges++;
        }

        return nChanges;
    }

    protected static final String GRANT_ERROR = "grantError";

    public static final String GRANT_TRUSTEDMGR_PRIVILEGE = "grantTrustedManagerPrivilege";
    public static final String GRANT_CMAGENT_PRIVILEGE = "grantCMAgentPrivilege";
    public static final String GRANT_RMAGENT_PRIVILEGE = "grantRMAgentPrivilege";
    public static final String GRANT_DRMAGENT_PRIVILEGE = "grantDRMAgentPrivilege";
    public static final String GRANT_UID = "grantUID";
    public static final String GRANT_PRIVILEGE = "grantPrivilege";

    protected int grant_privileges(
            CMSRequest cmsReq, IRequest req, Certificate[] certs, IArgBlock header)
            throws EBaseException {
        // get privileges to grant
        IArgBlock httpParams = cmsReq.getHttpParams();

        boolean grantTrustedMgr =
                httpParams.getValueAsBoolean(GRANT_TRUSTEDMGR_PRIVILEGE, false);
        boolean grantRMAgent =
                httpParams.getValueAsBoolean(GRANT_RMAGENT_PRIVILEGE, false);
        boolean grantCMAgent =
                httpParams.getValueAsBoolean(GRANT_CMAGENT_PRIVILEGE, false);
        boolean grantDRMAgent =
                httpParams.getValueAsBoolean(GRANT_DRMAGENT_PRIVILEGE, false);

        if (!grantTrustedMgr &&
                !grantCMAgent && !grantRMAgent && !grantDRMAgent) {
            return 0;
        } else {
            IAuthToken authToken = getAuthToken(req);
            AuthzToken authzToken = null;
            String resourceName = "certServer." + mAuthority.getId() + ".group";

            try {
                authzToken = authorize(mAclMethod, authToken,
                            resourceName, "add");
            } catch (Exception e) {
                // do nothing for now
            }

            if (authzToken == null) {
                String[] obj = new String[1];

                if (grantTrustedMgr)
                    obj[0] = TRUSTED_RA_GROUP;
                else if (grantRMAgent)
                    obj[0] = RA_AGENT_GROUP;
                else if (grantCMAgent)
                    obj[0] = CA_AGENT_GROUP;
                else if (grantDRMAgent)
                    obj[0] = KRA_AGENT_GROUP;
                else
                    obj[0] = "unknown group";

                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_UNAUTHORIZED_CREATE_GROUP", obj[0]));
            }
        }

        String uid = httpParams.getValueAsString(GRANT_UID, null);

        if (uid == null || uid.length() == 0) {
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_MISSING_GRANT_UID"));
        }
        header.addStringValue(GRANT_UID, uid);

        String groupname = null, groupname1 = null;
        String userType = "";

        if (grantTrustedMgr) {
            groupname = TRUSTED_RA_GROUP;
            userType = Constants.PR_SUBSYSTEM_TYPE;
        } else {
            if (grantCMAgent)
                groupname = CA_AGENT_GROUP;
            else if (grantRMAgent)
                groupname = RA_AGENT_GROUP;

            if (grantDRMAgent) {
                if (groupname != null)
                    groupname1 = KRA_AGENT_GROUP;
                else
                    groupname = KRA_AGENT_GROUP;
            }
            userType = Constants.PR_AGENT_TYPE;
        }

        String privilege =
                (groupname1 == null) ? groupname : groupname + " and " + groupname1;

        header.addStringValue(GRANT_PRIVILEGE, privilege);

        IUGSubsystem ug = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
        IUser user = ug.createUser(uid);

        user.setFullName(uid);
        user.setEmail("");
        user.setPhone("");
        user.setPassword("");
        user.setUserType(userType);
        user.setState("1");
        IGroup group = ug.findGroup(groupname), group1 = null;

        if (group == null) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_FIND_GROUP_1", groupname));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_FIND_GROUP_ERROR", groupname));
        }
        if (groupname1 != null) {
            group1 = ug.findGroup(groupname1);
            if (group1 == null) {
                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_ERROR_FIND_GROUP_1", groupname));
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_FIND_GROUP_ERROR", groupname1));
            }
        }
        try {
            ug.addUser(user);
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_ADDING_USER_1", uid));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_ADDING_USER_ERROR", uid));
        }
        try {
            if (certs[0] instanceof X509CertImpl) {
                X509CertImpl tmp[] = (X509CertImpl[]) certs;

                user.setX509Certificates(tmp);
            }

            ug.addUserCert(user);
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERROR_ADDING_CERT_1", uid));
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_ADDING_CERT_ERROR", uid));
        }
        try {
            group.addMemberName(uid);
            ug.modifyGroup(group);
            // for audit log
            SessionContext sContext = SessionContext.getContext();
            String adminId = (String) sContext.get(SessionContext.USER_ID);

            mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                    AuditFormat.LEVEL, AuditFormat.ADDUSERGROUPFORMAT,
                    new Object[] { adminId, uid, groupname }
                    );

            if (group1 != null) {
                group1.addMemberName(uid);
                ug.modifyGroup(group1);

                mLogger.log(ILogger.EV_AUDIT, ILogger.S_USRGRP,
                        AuditFormat.LEVEL, AuditFormat.ADDUSERGROUPFORMAT,
                        new Object[] { adminId, uid, groupname1 }
                        );

            }
        } catch (Exception e) {
            String msg =
                    "Could not add user " + uid + " to group " + groupname;

            if (group1 != null)
                msg += " or group " + groupname1;
            log(ILogger.LL_FAILURE, msg);
            if (group1 == null)
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_ADDING_MEMBER", uid, groupname));
            else
                throw new ECMSGWException(CMS.getUserMessage("CMS_GW_ADDING_MEMBER_1", uid, groupname, groupname1));
        }
        return 1;
    }

    /**
     * Signed Audit Log Info Name
     *
     * This method is called to obtain the "InfoName" for
     * a signed audit log message.
     * <P>
     *
     * @param type signed audit log request processing type
     * @return id string containing the signed audit log message InfoName
     */
    private String auditInfoName(String type) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters (this is done below)

        String infoName = ILogger.UNIDENTIFIED;

        if (mSignedAuditLogger == null) {
            return infoName;
        }

        if (type != null) {
            type = type.trim();

            if (type.equals(SIGNED_AUDIT_ACCEPTANCE)) {
                infoName = ILogger.SIGNED_AUDIT_ACCEPTANCE;
            } else if (type.equals(SIGNED_AUDIT_CANCELLATION)) {
                infoName = ILogger.SIGNED_AUDIT_CANCELLATION;
            } else if (type.equals(SIGNED_AUDIT_REJECTION)) {
                infoName = ILogger.SIGNED_AUDIT_REJECTION;
            }
        }

        return infoName;
    }

    /**
     * Signed Audit Log Info Certificate Value
     *
     * This method is called to obtain the certificate from the passed in
     * "X509CertImpl" for a signed audit log message.
     * <P>
     *
     * @param x509cert an X509CertImpl
     * @return cert string containing the certificate
     */
    private String auditInfoCertValue(X509CertImpl x509cert) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        if (x509cert == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = null;

        try {
            rawData = x509cert.getEncoded();
        } catch (CertificateEncodingException e) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        String cert = null;

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = null;

            base64Data = Utils.base64encode(rawData).trim();

            // extract all line separators from the "base64Data"
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < base64Data.length(); i++) {
                if (base64Data.substring(i, i).getBytes() != EOL) {
                    sb.append(base64Data.substring(i, i));
                }
            }
            cert = sb.toString();
        }

        if (cert != null) {
            cert = cert.trim();

            if (cert.equals("")) {
                return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            } else {
                return cert;
            }
        } else {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
    }
}

class RAReqCompletedFiller extends ImportCertsTemplateFiller {
    private static final String RA_AGENT_GROUP = "Registration Manager Agents";
    private static final String KRA_AGENT_GROUP = "Data Recovery Manager Agents";

    public RAReqCompletedFiller() {
        super();
    }

    public CMSTemplateParams getTemplateParams(
            CMSRequest cmsReq, IAuthority authority, Locale locale, Exception e)
            throws Exception {

        Object[] results = (Object[]) cmsReq.getResult();
        Object grantError = results[1];
        //X509CertImpl[] issuedCerts = (X509CertImpl[])results[0];
        Certificate[] issuedCerts = (Certificate[]) results[0];

        cmsReq.setResult(issuedCerts);
        CMSTemplateParams params =
                super.getTemplateParams(cmsReq, authority, locale, e);

        if (grantError != null) {
            IArgBlock header = params.getHeader();

            if (grantError instanceof String) {
                header.addStringValue(
                        ProcessCertReq.GRANT_ERROR, (String) grantError);
            } else {
                EBaseException ex = (EBaseException) grantError;

                header.addStringValue(
                        ProcessCertReq.GRANT_ERROR, ex.toString(locale));
            }
            IArgBlock httpParams = cmsReq.getHttpParams();
            String uid = httpParams.getValueAsString(
                    ProcessCertReq.GRANT_UID, null);

            header.addStringValue(ProcessCertReq.GRANT_UID, uid);
            boolean grantRMAgent = httpParams.getValueAsBoolean(
                    ProcessCertReq.GRANT_RMAGENT_PRIVILEGE, false);
            boolean grantDRMAgent = httpParams.getValueAsBoolean(
                    ProcessCertReq.GRANT_DRMAGENT_PRIVILEGE, false);
            String privilege = null;

            if (grantRMAgent) {
                privilege = RA_AGENT_GROUP;
            }
            if (grantDRMAgent) {
                if (privilege != null)
                    privilege += " and " + KRA_AGENT_GROUP;
                else
                    privilege = KRA_AGENT_GROUP;
            }
            header.addStringValue(ProcessCertReq.GRANT_PRIVILEGE, privilege);
        }
        return params;
    }
}
