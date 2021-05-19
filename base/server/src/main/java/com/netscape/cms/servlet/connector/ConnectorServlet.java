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
package com.netscape.cms.servlet.connector;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.mozilla.jss.netscape.security.x509.CRLExtensions;
import org.mozilla.jss.netscape.security.x509.CRLReasonExtension;
import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.RevocationReason;
import org.mozilla.jss.netscape.security.x509.RevokedCertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.connector.IRequestEncoder;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.event.CertRequestProcessedEvent;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.profile.common.EnrollProfile;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.connector.HttpPKIMessage;
import com.netscape.cmscore.connector.HttpRequestEncoder;
import com.netscape.cmscore.request.RequestQueue;

/**
 * Connector servlet
 * process requests from remote authority -
 * service request or return status.
 *
 * @author cfu - Server-Side Keygen Enrollment implementation
 */
public class ConnectorServlet extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ConnectorServlet.class);

    private static final long serialVersionUID = 1221916495803185863L;
    public static final String INFO = "Connector Servlet";
    public final static String PROP_AUTHORITY = "authority";
    protected ServletConfig mConfig = null;
    protected IAuthority mAuthority = null;
    protected IRequestEncoder mReqEncoder = null;
    protected AuthSubsystem mAuthSubsystem;

    private final static String SIGNED_AUDIT_PROTECTION_METHOD_SSL = "ssl";

    public ConnectorServlet() {
    }

    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        CMSEngine engine = CMS.getCMSEngine();
        mConfig = sc;
        String authority = sc.getInitParameter(PROP_AUTHORITY);

        if (authority != null)
            mAuthority = (IAuthority) engine.getSubsystem(authority);
        mReqEncoder = new HttpRequestEncoder();

        mAuthSubsystem = engine.getAuthSubsystem();
    }

    @Override
    public void service(HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        CMSEngine engine = CMS.getCMSEngine();
        boolean running_state = engine.isInRunningState();

        if (!running_state)
            throw new IOException(
                    "CMS server is not ready to serve.");

        HttpServletRequest req = request;
        HttpServletResponse resp = response;

        CMSRequest cmsRequest = newCMSRequest();

        // set argblock
        cmsRequest.setHttpParams(new ArgBlock(toHashtable(request)));

        // set http request
        cmsRequest.setHttpReq(request);

        // set http response
        cmsRequest.setHttpResp(response);

        // set servlet config.
        cmsRequest.setServletConfig(mConfig);

        // set servlet context.
        cmsRequest.setServletContext(mConfig.getServletContext());

        char[] content = null;
        String encodedreq = null;
        String method = null;
        int len = -1;
        IPKIMessage msg = null;
        IPKIMessage replymsg = null;

        // NOTE must read all bufer before redoing handshake for
        // ssl client auth for client auth to work.

        // get request method
        method = req.getMethod();

        // get content length
        len = request.getContentLength();

        // get content, a base 64 encoded serialized request.
        if (len > 0) {
            InputStream in = request.getInputStream();
            InputStreamReader inreader = new InputStreamReader(in, "UTF8");
            BufferedReader reader = new BufferedReader(inreader, len);

            content = new char[len];
            int done = reader.read(content, 0, len);
            int total = done;

            while (done >= 0 && total < len) {
                done = reader.read(content, total, len - total);
                total += done;
            }
            reader.close();
            encodedreq = new String(content);
        }

        // force client auth handshake, validate RA and get RA's Id.
        // NOTE must do this after all contents are read for ssl
        // redohandshake to work

        X509Certificate peerCert;

        try {
            peerCert = getPeerCert(req);
        } catch (EBaseException e) {
            logger.warn(CMS.getLogMessage("CMSGW_HAS_NO_CLIENT_CERT"), e);
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        if (peerCert == null) {
            // XXX log something here.
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        // authenticate RA

        String RA_Id = null;
        String raUserId = null;
        IAuthToken token = null;

        try {
            token = authenticate(request);
            raUserId = token.getInString("userid");
            RA_Id = peerCert.getSubjectDN().toString();
        } catch (EInvalidCredentials e) {
            // already logged.
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        } catch (EBaseException e) {
            // already logged.
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        logger.info("ConnectorServlet: Remote Authority authenticated: " + peerCert.getSubjectDN());

        // authorize
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, token,
                        mAuthzResourceName, "submit");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsRequest.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        // after cert validated, check http request.
        if (!method.equalsIgnoreCase("POST")) {
            resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        if (len <= 0) {
            resp.sendError(HttpServletResponse.SC_LENGTH_REQUIRED);
            return;
        }

        // now process request.

        logger.debug("ConnectorServlet: process request RA_Id=" + RA_Id);
        try {
            // decode request.
            msg = (IPKIMessage) mReqEncoder.decode(encodedreq);
            // process request
            replymsg = processRequest(RA_Id, raUserId, msg, token);
        } catch (IOException e) {
            logger.error("ConnectorServlet: service " + e.getMessage(), e);
            logger.error(CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        } catch (EBaseException e) {
            logger.error("ConnectorServlet: service " + e.getMessage(), e);
            logger.error(CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        } catch (Exception e) {
            logger.warn("ConnectorServlet: service " + e.getMessage(), e);
        }

        logger.debug("ConnectorServlet: done processRequest");

        // encode reply
        try {
            String encodedrep = mReqEncoder.encode(replymsg);

            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType("text/html");
            resp.setContentLength(encodedrep.length());

            // send reply
            OutputStream out = response.getOutputStream();
            OutputStreamWriter writer = new OutputStreamWriter(out, "UTF8");

            writer.write(encodedrep);
            writer.flush();
            writer.close();
            out.flush();
        } catch (Exception e) {
            logger.warn("ConnectorServlet: error writing e=" + e.getMessage(), e);
        }
        logger.debug("ConnectorServlet: send response RA_Id=" + RA_Id);
    }

    public static boolean isProfileRequest(IRequest request) {
        String profileId = request.getExtDataInString(IRequest.PROFILE_ID);

        if (profileId == null || profileId.equals(""))
            return false;
        else
            return true;
    }

    public void normalizeProfileRequest(IRequest request) {
        // if it is profile request, we need to normalize the
        // x509certinfo from ra into request
        X509CertInfo info = null;
        ByteArrayOutputStream byteStream;
        CMSEngine engine = CMS.getCMSEngine();

        try {
            info = request.getExtDataInCertInfo(EnrollProfile.REQUEST_CERTINFO);

            //   request.set(IEnrollProfile.REQUEST_SEQ_NUM, Integer.valueOf("0"));
            CertificateX509Key certKey = (CertificateX509Key) info.get(X509CertInfo.KEY);
            if (certKey != null) {
                byteStream = new ByteArrayOutputStream();
                certKey.encode(byteStream);
                request.setExtData(IRequest.REQUEST_KEY,
                        byteStream.toByteArray());
            }

            CertificateSubjectName certSubject = (CertificateSubjectName)
                    info.get(X509CertInfo.SUBJECT);
            if (certSubject != null) {
                request.setExtData(IRequest.REQUEST_SUBJECT_NAME,
                        certSubject);
            }

            CertificateValidity certValidity = (CertificateValidity)
                    info.get(X509CertInfo.VALIDITY);
            if (certValidity != null) {
                byteStream = new ByteArrayOutputStream();
                certValidity.encode(byteStream);
                request.setExtData(EnrollProfile.REQUEST_VALIDITY,
                        byteStream.toByteArray());
            }

            CertificateExtensions extensions = (CertificateExtensions)
                    info.get(X509CertInfo.EXTENSIONS);
            if (extensions != null) {
                request.setExtData(EnrollProfile.REQUEST_EXTENSIONS,
                        extensions);
            }

            CertificateAlgorithmId certAlg = (CertificateAlgorithmId)
                    info.get(X509CertInfo.ALGORITHM_ID);
            if (certAlg != null) {
                ByteArrayOutputStream certAlgOut = new ByteArrayOutputStream();
                certAlg.encode(certAlgOut);
                request.setExtData(EnrollProfile.REQUEST_SIGNING_ALGORITHM,
                        certAlgOut.toByteArray());
            }
        } catch (Exception e) {
            logger.warn("ConnectorServlet: profile normalization " + e.getMessage(), e);
        }
    }

    /**
     * Process request
     * <P>
     *
     * (Certificate Request - all "agent" profile cert requests made through a connector)
     * <P>
     *
     * (Certificate Request Processed - all automated "agent" profile based cert acceptance made through a connector)
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST used when a profile cert request is made (before
     * approval process)
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED used when a certificate request has just been
     * through the approval process
     * <li>signed.audit LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS used when inter-CIMC_Boundary data transfer is
     * successful (this is used when data does not need to be captured)
     * </ul>
     *
     * @param source string containing source
     * @param sourceUserId string containing source user ID
     * @param msg PKI message
     * @param token the authentication token
     * @exception EBaseException an error has occurred
     * @return PKI message
     */
    protected IPKIMessage processRequest(
            String source, String sourceUserId, IPKIMessage msg, IAuthToken token)
            throws EBaseException {

        String method = "ConnectorServlet: processRequest: ";
        String auditMessage = null;
        String auditSubjectID = sourceUserId;
        String auditProtectionMethod = SIGNED_AUDIT_PROTECTION_METHOD_SSL;
        String auditRequestType = msg.getReqType();
        String auditRequesterID = msg.getReqId();

        // additional parms for LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST
        String auditCertificateSubjectName = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        String subject = null;

        // "normalize" the "auditSubjectID"
        if (auditSubjectID != null) {
            auditSubjectID = auditSubjectID.trim();
        } else {
            auditSubjectID = ILogger.UNIDENTIFIED;
        }

        // "normalize" the "auditRequestType"
        if (auditRequestType != null) {
            auditRequestType = auditRequestType.trim();
        } else {
            auditRequestType = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        // "normalize" the "auditRequesterID"
        if (auditRequesterID != null) {
            auditRequesterID = auditRequesterID.trim();
        } else {
            auditRequesterID = ILogger.UNIDENTIFIED;
        }

        CMSEngine engine = CMS.getCMSEngine();

        IPKIMessage replymsg = null;

        try {
            RequestQueue queue = engine.getRequestQueue();
            String srcid = source + ":" + msg.getReqId();
            logger.debug(method + "srcid =" + srcid);

            // find request in request queue and return result.
            RequestId thisreqid = queue.findRequestBySourceId(srcid);
            IRequest thisreq = null;

            if (thisreqid != null) {
                logger.debug(method + "thisreqid not null:" + thisreqid);
                thisreq = requestRepository.readRequest(thisreqid);
                if (thisreq == null) {
                    // strange case.
                    String errormsg = "Cannot find request in request queue " +
                            thisreqid;

                    logger.error(method + CMS.getLogMessage(
                                    "CMSGW_REQUEST_ID_NOT_FOUND_1",
                                    thisreqid.toString()));

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                AuditEvent.INTER_BOUNDARY,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditProtectionMethod,
                                auditRequestType,
                                auditRequesterID);

                    audit(auditMessage);

                    // NOTE:  The signed audit event
                    //        LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST
                    //        does not yet matter at this point!

                    throw new EBaseException(errormsg);
                } else {
                    String errormsg = "Found request " + thisreqid + " for " + srcid;
                    // for Server-Side Keygen, it could be the 2nd trip
                    // where stage was Request.SSK_STAGE_KEYGEN going on
                    // IRequest.SSK_STAGE_KEY_RETRIEVE
                    String sskKeygenStage = thisreq.getExtDataInString(IRequest.SSK_STAGE);
                    if (sskKeygenStage!= null && sskKeygenStage.equalsIgnoreCase(IRequest.SSK_STAGE_KEYGEN)) {
                        logger.debug("ConnectorServlet:processRequest: Stage=" + sskKeygenStage);
                    } else {

                        logger.debug(method + errormsg);

                        replymsg = new HttpPKIMessage();
                        replymsg.fromRequest(thisreq);

                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    AuditEvent.INTER_BOUNDARY,
                                    auditSubjectID,
                                    ILogger.SUCCESS,
                                    auditProtectionMethod,
                                    auditRequestType,
                                    auditRequesterID);

                        audit(auditMessage);

                        // NOTE:  The signed audit event
                        //        LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST
                        //        does not yet matter at this point!

                        return replymsg;
                    }
                }
            }

            // if not found process request.
            thisreq = requestRepository.createRequest(msg.getReqType());
            // debug
            // CertUtils.printRequestContent(thisreq);

            logger.debug("ConnectorServlet: created requestId=" +
                    thisreq.getRequestId().toString());
            thisreq.setSourceId(srcid);

            // NOTE:  For the following signed audit message, since we only
            //        care about the "msg.toRequest( thisreq );" command, and
            //        since this command does not throw an EBaseException
            //        (which is the only exception designated by this method),
            //        then this code does NOT need to be contained within its
            //        own special try/catch block.
            msg.toRequest(thisreq);

            // reset CA's request dbStatus and requestStatus got inadvertantly
            // transferred over
            thisreq.setExtData("dbStatus", "NOT_UPDATED");
            thisreq.setExtData(IRequest.REQ_STATUS, "begin");

            boolean isSSKeygen = false;
            String isSSKeygenStr = thisreq.getExtDataInString("isServerSideKeygen");
            if ((isSSKeygenStr != null) && isSSKeygenStr.equalsIgnoreCase("true")) {
                logger.debug("ConnectorServlet:isServerSideKeygen = true");
                isSSKeygen = true;
                String sskKeygenStage = thisreq.getExtDataInString(IRequest.SSK_STAGE);
                if (sskKeygenStage!= null && sskKeygenStage.equalsIgnoreCase(IRequest.SSK_STAGE_KEYGEN)) {
                    logger.debug(method + "isServerSideKeygen Stage=" + sskKeygenStage);
                    thisreq.setRequestType("asymkeyGenRequest"); //IRequest.ASYMKEY_GENERATION_REQUEST
                } else if (sskKeygenStage.equalsIgnoreCase(IRequest.SSK_STAGE_KEY_RETRIEVE)) {
                    logger.debug(method + "isServerSideKeygen Stage=" + sskKeygenStage);
                    thisreq.setRequestType("recovery"); //IRequest.KEYRECOVERY_REQUEST
                }
                String clientKeyId = thisreq.getExtDataInString(IRequest.SECURITY_DATA_CLIENT_KEY_ID);
                if (clientKeyId != null)
                    logger.debug(method + "isServerSideKeygen clientKeyId = " + clientKeyId);
                else
                    logger.debug(method + "isServerSideKeygen clientKeyId not found");
            } else {
                logger.debug("ConnectorServlet:isServerSideKeygen = false");
            }

            if (isProfileRequest(thisreq)) {
                X509CertInfo info =
                                    thisreq.getExtDataInCertInfo(
                                            EnrollProfile.REQUEST_CERTINFO);

                try {
                    CertificateSubjectName sn = (CertificateSubjectName)
                            info.get(X509CertInfo.SUBJECT);

                    // if the cert subject name is NOT MISSING, retrieve the
                    // actual "auditCertificateSubjectName" and "normalize"
                    // it
                    if (sn != null) {
                        subject = sn.toString();
                        if (subject != null) {
                            // NOTE:  This is ok even if the cert subject
                            //        name is "" (empty)!
                            auditCertificateSubjectName = subject.trim();
                        }
                    }

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            AuditEvent.PROFILE_CERT_REQUEST,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRequesterID,
                            auditProfileID(),
                            auditCertificateSubjectName);

                    audit(auditMessage);
                } catch (CertificateException e) {
                    logger.warn("ConnectorServlet: processRequest " + e.getMessage(), e);

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            AuditEvent.PROFILE_CERT_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditProfileID(),
                            auditCertificateSubjectName);

                    audit(auditMessage);
                } catch (IOException e) {
                    logger.warn("ConnectorServlet: processRequest " + e.getMessage(), e);

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            AuditEvent.PROFILE_CERT_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditProfileID(),
                            auditCertificateSubjectName);

                    audit(auditMessage);
                }
            }

            thisreq.setExtData(IRequest.AUTH_TOKEN, token);

            if (StringUtils.isNotEmpty(msg.getReqRealm())) {
                thisreq.setRealm(msg.getReqRealm());
            }

            // setting requestor type must come after copy contents. because
            // requestor is a regular attribute.
            thisreq.setExtData(IRequest.REQUESTOR_TYPE,
                    IRequest.REQUESTOR_RA);
            logger.info("ConnectorServlet: Processing remote request " + srcid);

            // Set this so that request's updateBy is recorded
            SessionContext s = SessionContext.getContext();

            if (s.get(SessionContext.USER_ID) == null) {
                s.put(SessionContext.USER_ID, sourceUserId);
            }

            if (s.get(SessionContext.REQUESTER_ID) == null) {
                s.put(SessionContext.REQUESTER_ID, msg.getReqId());
            }

            //logger.debug("ConnectorServlet: calling processRequest instance=" +
            //        thisreq);
            if (isProfileRequest(thisreq)) {
                normalizeProfileRequest(thisreq);
            }

            logger.debug("ConnectorServlet: calling processRequest");
            try {
                queue.processRequest(thisreq);

            } finally {

                if (isProfileRequest(thisreq)) {

                    X509CertImpl x509cert = thisreq.getExtDataInCert(EnrollProfile.REQUEST_ISSUED_CERT);

                    if (x509cert != null) {

                        audit(CertRequestProcessedEvent.createSuccessEvent(
                                auditSubjectID,
                                auditRequesterID,
                                ILogger.SIGNED_AUDIT_ACCEPTANCE,
                                x509cert));

                    } else {

                        audit(CertRequestProcessedEvent.createFailureEvent(
                                auditSubjectID,
                                auditRequesterID,
                                ILogger.SIGNED_AUDIT_REJECTION,
                                ILogger.SIGNED_AUDIT_EMPTY_VALUE));
                    }
                }
            }

            replymsg = new HttpPKIMessage();
            replymsg.fromRequest(thisreq);

            logger.debug("ConnectorServlet: replymsg.reqStatus=" +
                    replymsg.getReqStatus());

            //for audit log
            String agentID = sourceUserId;
            String initiative = AuditFormat.FROMRA + " trustedManagerID: " +
                    agentID + " remote reqID " + msg.getReqId();
            String authMgr = AuditFormat.NOAUTH;

            if (token != null) {
                authMgr =
                        token.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
            }

            if (isProfileRequest(thisreq)) {
                // XXX audit log
                logger.debug("ConnectorServlet: done requestId=" +
                        thisreq.getRequestId().toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.INTER_BOUNDARY,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditProtectionMethod,
                            auditRequestType,
                            auditRequesterID);

                audit(auditMessage);

                // NOTE:  The signed audit event
                //        LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST
                //        has already been logged at this point!

                return replymsg;
            }

            // Get the certificate info from the request
            X509CertInfo x509Info[] = thisreq.getExtDataInCertInfoArray(IRequest.CERT_INFO);

            try {
                if (!thisreq.getRequestStatus().equals(RequestStatus.COMPLETE)) {
                    if (x509Info != null) {
                        for (int i = 0; i < x509Info.length; i++) {
                            logger.info(
                                    AuditFormat.FORMAT,
                                    thisreq.getRequestType(),
                                    thisreq.getRequestId(),
                                    initiative,
                                    authMgr,
                                    thisreq.getRequestStatus(),
                                    x509Info[i].get(X509CertInfo.SUBJECT),
                                    ""
                            );
                        }
                    } else {
                        logger.info(
                                AuditFormat.NODNFORMAT,
                                thisreq.getRequestType(),
                                thisreq.getRequestId(),
                                initiative,
                                authMgr,
                                thisreq.getRequestStatus()
                        );
                    }
                } else {
                    if (thisreq.getRequestType().equals(IRequest.ENROLLMENT_REQUEST)) {
                        // XXX make the repeat record.
                        // Get the certificate(s) from the request
                        X509CertImpl x509Certs[] = null;

                        if (x509Info != null)
                            x509Certs =
                                    thisreq.getExtDataInCertArray(IRequest.ISSUED_CERTS);

                        // return potentially more than one certificates.
                        if (x509Certs != null) {
                            for (int i = 0; i < x509Certs.length; i++) {
                                logger.info(
                                        AuditFormat.FORMAT,
                                        thisreq.getRequestType(),
                                        thisreq.getRequestId(),
                                        initiative,
                                        authMgr,
                                        "completed",
                                        x509Certs[i].getSubjectDN(),
                                        "cert issued serial number: 0x" +
                                                x509Certs[i].getSerialNumber().toString(16)
                                );
                            }
                        } else {
                            logger.info(
                                    AuditFormat.NODNFORMAT,
                                    thisreq.getRequestType(),
                                    thisreq.getRequestId(),
                                    initiative,
                                    authMgr,
                                    "completed"
                            );
                        }
                    } else if (thisreq.getRequestType().equals(IRequest.RENEWAL_REQUEST)) {
                        X509CertImpl[] certs =
                                thisreq.getExtDataInCertArray(IRequest.OLD_CERTS);
                        X509CertImpl old_cert = certs[0];

                        certs = thisreq.getExtDataInCertArray(IRequest.ISSUED_CERTS);
                        X509CertImpl renewed_cert = certs[0];

                        if (old_cert != null && renewed_cert != null) {
                            logger.info(
                                    AuditFormat.RENEWALFORMAT,
                                    thisreq.getRequestId(),
                                    initiative,
                                    authMgr,
                                    "completed",
                                    old_cert.getSubjectDN(),
                                    old_cert.getSerialNumber().toString(16),
                                    "new serial number: 0x" +
                                            renewed_cert.getSerialNumber().toString(16)
                            );
                        } else {
                            logger.info(
                                    AuditFormat.NODNFORMAT,
                                    thisreq.getRequestType(),
                                    thisreq.getRequestId(),
                                    initiative,
                                    authMgr,
                                    "completed with error"
                            );
                        }
                    } else if (thisreq.getRequestType().equals(IRequest.REVOCATION_REQUEST)) {
                        Certificate[] oldCerts =
                                thisreq.getExtDataInCertArray(IRequest.OLD_CERTS);
                        RevokedCertImpl crlentries[] =
                                thisreq.getExtDataInRevokedCertArray(IRequest.REVOKED_CERTS);
                        CRLExtensions crlExts = crlentries[0].getExtensions();
                        int reason = 0;

                        if (crlExts != null) {
                            Enumeration<Extension> enum1 = crlExts.getElements();

                            while (enum1.hasMoreElements()) {
                                Extension ext = enum1.nextElement();

                                if (ext instanceof CRLReasonExtension) {
                                    reason = ((CRLReasonExtension) ext).getReason().toInt();
                                    break;
                                }
                            }
                        }

                        int count = oldCerts.length;
                        Integer result = thisreq.getExtDataInInteger(IRequest.RESULT);

                        if (result.equals(IRequest.RES_ERROR)) {
                            String[] svcErrors =
                                    thisreq.getExtDataInStringArray(IRequest.SVCERRORS);

                            if (svcErrors != null && svcErrors.length > 0) {
                                for (int i = 0; i < svcErrors.length; i++) {
                                    String err = svcErrors[i];

                                    if (err != null) {
                                        for (int j = 0; j < count; j++) {
                                            if (oldCerts[j] != null) {
                                                if (oldCerts[j] instanceof X509CertImpl) {
                                                    X509CertImpl cert = (X509CertImpl) oldCerts[j];

                                                    logger.info(
                                                            AuditFormat.DOREVOKEFORMAT,
                                                            thisreq.getRequestId(),
                                                            initiative,
                                                            "completed with error: " + err,
                                                            cert.getSubjectDN(),
                                                            cert.getSerialNumber().toString(16),
                                                            RevocationReason.fromInt(reason)
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            // the success.
                            for (int j = 0; j < count; j++) {
                                if (oldCerts[j] != null) {
                                    if (oldCerts[j] instanceof X509CertImpl) {
                                        X509CertImpl cert = (X509CertImpl) oldCerts[j];

                                        logger.info(
                                                AuditFormat.DOREVOKEFORMAT,
                                                thisreq.getRequestId(),
                                                initiative,
                                                "completed",
                                                cert.getSubjectDN(),
                                                cert.getSerialNumber().toString(16),
                                                RevocationReason.fromInt(reason)
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        logger.info(
                                AuditFormat.NODNFORMAT,
                                thisreq.getRequestType(),
                                thisreq.getRequestId(),
                                initiative,
                                authMgr,
                                "completed"
                        );
                    }
                }

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.INTER_BOUNDARY,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditProtectionMethod,
                            auditRequestType,
                            auditRequesterID);

                audit(auditMessage);
            } catch (IOException e) {
                logger.warn("ConnectorServlet: process " + e.getMessage(), e);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.INTER_BOUNDARY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProtectionMethod,
                            auditRequestType,
                            auditRequesterID);

                audit(auditMessage);
            } catch (CertificateException e) {
                logger.warn("ConnectorServlet: process " + e.getMessage(), e);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.INTER_BOUNDARY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProtectionMethod,
                            auditRequestType,
                            auditRequesterID);

                audit(auditMessage);
            } catch (Exception e) {
                logger.warn("ConnectorServlet: process " + e.getMessage(), e);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            AuditEvent.INTER_BOUNDARY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProtectionMethod,
                            auditRequestType,
                            auditRequesterID);

                audit(auditMessage);
            } finally {
                SessionContext.releaseContext();
            }

            // NOTE:  The signed audit event
            //        LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST
            //        has already been logged at this point!

            return replymsg;
        } catch (EBaseException e) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.INTER_BOUNDARY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditProtectionMethod,
                        auditRequestType,
                        auditRequesterID);

            audit(auditMessage);

            // NOTE:  The signed audit event
            //        LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST
            //        has either already been logged, or
            //        does not yet matter at this point!

            return replymsg;
        }
    }

    protected X509Certificate
            getPeerCert(HttpServletRequest req) throws EBaseException {
        return getSSLClientCertificate(req);
    }

    @Override
    public String getServletInfo() {
        return INFO;
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
    @Override
    protected void audit(String msg) {
        signedAuditLogger.log(msg);
    }

    @Override
    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }

    /**
     * Signed Audit Log Profile ID
     *
     * This method is inherited by all extended "EnrollProfile"s,
     * and is called to obtain the "ProfileID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message ProfileID
     */
    protected String auditProfileID() {

        String profileID = getId();

        if (profileID != null) {
            profileID = profileID.trim();
        } else {
            profileID = ILogger.UNIDENTIFIED;
        }

        return profileID;
    }
}
