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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.CRLExtensions;
import netscape.security.x509.CRLReasonExtension;
import netscape.security.x509.CertificateAlgorithmId;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateValidity;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.Extension;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.RevokedCertImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authority.IAuthority;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.connector.IPKIMessage;
import com.netscape.certsrv.connector.IRequestEncoder;
import com.netscape.certsrv.logging.AuditFormat;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IEnrollProfile;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmsutil.util.Utils;

/**
 * Connector servlet
 * process requests from remote authority -
 * service request or return status.
 *
 * @version $Revision$, $Date$
 */
public class ConnectorServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = 1221916495803185863L;
    public static final String INFO = "Connector Servlet";
    public final static String PROP_AUTHORITY = "authority";
    protected ServletConfig mConfig = null;
    protected IAuthority mAuthority = null;
    protected IRequestEncoder mReqEncoder = null;
    protected IAuthSubsystem mAuthSubsystem = null;
    protected ILogger mLogger = CMS.getLogger();

    protected ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    private final static String SIGNED_AUDIT_PROTECTION_METHOD_SSL = "ssl";
    private final static String LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS =
            "LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS_5";
    private final static String LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST =
            "LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST_5";
    private final static String LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED =
            "LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED_5";

    private final static byte EOL[] = { Character.LINE_SEPARATOR };

    public ConnectorServlet() {
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mConfig = sc;
        String authority = sc.getInitParameter(PROP_AUTHORITY);

        if (authority != null)
            mAuthority = (IAuthority)
                    CMS.getSubsystem(authority);
        mReqEncoder = CMS.getHttpRequestEncoder();

        mAuthSubsystem = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
    }

    public void service(HttpServletRequest request,
            HttpServletResponse response)
            throws ServletException, IOException {

        boolean running_state = CMS.isInRunningState();

        if (!running_state)
            throw new IOException(
                    "CMS server is not ready to serve.");

        HttpServletRequest req = request;
        HttpServletResponse resp = response;

        CMSRequest cmsRequest = newCMSRequest();

        // set argblock
        cmsRequest.setHttpParams(CMS.createArgBlock(toHashtable(request)));

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
            mAuthority.log(ILogger.LL_SECURITY,
                    CMS.getLogMessage("CMSGW_HAS_NO_CLIENT_CERT"));
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

        mAuthority.log(ILogger.LL_INFO,
                "Remote Authority authenticated: " + peerCert.getSubjectDN());

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

        CMS.debug("ConnectorServlet: process request RA_Id=" + RA_Id);
        try {
            // decode request.
            msg = (IPKIMessage) mReqEncoder.decode(encodedreq);
            // process request
            replymsg = processRequest(RA_Id, raUserId, msg, token);
        } catch (IOException e) {
            CMS.debug("ConnectorServlet: service " + e.toString());
            CMS.debug(e);
            mAuthority.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        } catch (EBaseException e) {
            CMS.debug("ConnectorServlet: service " + e.toString());
            CMS.debug(e);
            mAuthority.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        } catch (Exception e) {
            CMS.debug("ConnectorServlet: service " + e.toString());
            CMS.debug(e);
        }

        CMS.debug("ConnectorServlet: done processRequest");

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
            CMS.debug("ConnectorServlet: error writing e=" + e.toString());
        }
        CMS.debug("ConnectorServlet: send response RA_Id=" + RA_Id);
    }

    public static boolean isProfileRequest(IRequest request) {
        String profileId = request.getExtDataInString("profileId");

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

        try {
            info = request.getExtDataInCertInfo(IEnrollProfile.REQUEST_CERTINFO);

            //   request.set(IEnrollProfile.REQUEST_SEQ_NUM, new Integer("0"));
            CertificateX509Key certKey = (CertificateX509Key) info.get(X509CertInfo.KEY);
            if (certKey != null) {
                byteStream = new ByteArrayOutputStream();
                certKey.encode(byteStream);
                request.setExtData(IEnrollProfile.REQUEST_KEY,
                        byteStream.toByteArray());
            }

            CertificateSubjectName certSubject = (CertificateSubjectName)
                    info.get(X509CertInfo.SUBJECT);
            if (certSubject != null) {
                request.setExtData(IEnrollProfile.REQUEST_SUBJECT_NAME,
                        certSubject);
            }

            CertificateValidity certValidity = (CertificateValidity)
                    info.get(X509CertInfo.VALIDITY);
            if (certValidity != null) {
                byteStream = new ByteArrayOutputStream();
                certValidity.encode(byteStream);
                request.setExtData(IEnrollProfile.REQUEST_VALIDITY,
                        byteStream.toByteArray());
            }

            CertificateExtensions extensions = (CertificateExtensions)
                    info.get(X509CertInfo.EXTENSIONS);
            if (extensions != null) {
                request.setExtData(IEnrollProfile.REQUEST_EXTENSIONS,
                        extensions);
            }

            CertificateAlgorithmId certAlg = (CertificateAlgorithmId)
                    info.get(X509CertInfo.ALGORITHM_ID);
            if (certAlg != null) {
                ByteArrayOutputStream certAlgOut = new ByteArrayOutputStream();
                certAlg.encode(certAlgOut);
                request.setExtData(IEnrollProfile.REQUEST_SIGNING_ALGORITHM,
                        certAlgOut.toByteArray());
            }
        } catch (Exception e) {
            CMS.debug("ConnectorServlet: profile normalization " +
                    e.toString());
        }

        String profileId = request.getExtDataInString("profileId");
        IProfileSubsystem ps = (IProfileSubsystem)
                CMS.getSubsystem("profile");
        IEnrollProfile profile = null;

        // profile subsystem may not be available. In case of KRA for
        // example
        if (ps == null) {
            CMS.debug("ConnectorServlet: Profile Subsystem not found ");
            return;
        }
        try {
            profile = (IEnrollProfile) (ps.getProfile(profileId));
            profile.setDefaultCertInfo(request);
        } catch (EProfileException e) {
            CMS.debug("ConnectorServlet: normalizeProfileRequest Exception: " + e.toString());
        }
        if (profile == null) {
            CMS.debug("ConnectorServlet: Profile not found " + profileId);
            return;
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
        String auditMessage = null;
        String auditSubjectID = sourceUserId;
        String auditProtectionMethod = SIGNED_AUDIT_PROTECTION_METHOD_SSL;
        String auditRequestType = msg.getReqType();
        String auditRequesterID = msg.getReqId();

        // additional parms for LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST
        String auditCertificateSubjectName = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        String subject = null;

        // additional parms for LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED
        String auditInfoCertValue = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

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

        IPKIMessage replymsg = null;

        try {
            IRequestQueue queue = mAuthority.getRequestQueue();
            String srcid = source + ":" + msg.getReqId();

            // find request in request queue and return result.
            RequestId thisreqid = queue.findRequestBySourceId(srcid);
            IRequest thisreq = null;

            if (thisreqid != null) {
                thisreq = queue.findRequest(thisreqid);
                if (thisreq == null) {
                    // strange case.
                    String errormsg = "Cannot find request in request queue " +
                            thisreqid;

                    mAuthority.log(ILogger.LL_FAILURE,
                            CMS.getLogMessage(
                                    "CMSGW_REQUEST_ID_NOT_FOUND_1",
                                    thisreqid.toString()));

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS,
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
                    mAuthority.log(ILogger.LL_INFO,
                            "Found request " + thisreqid + " for " + srcid);
                    replymsg = CMS.getHttpPKIMessage();
                    replymsg.fromRequest(thisreq);

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS,
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

            // if not found process request.
            thisreq = queue.newRequest(msg.getReqType());
            CMS.debug("ConnectorServlet: created requestId=" +
                    thisreq.getRequestId().toString());
            thisreq.setSourceId(srcid);

            // NOTE:  For the following signed audit message, since we only
            //        care about the "msg.toRequest( thisreq );" command, and
            //        since this command does not throw an EBaseException
            //        (which is the only exception designated by this method),
            //        then this code does NOT need to be contained within its
            //        own special try/catch block.
            msg.toRequest(thisreq);

            if (isProfileRequest(thisreq)) {
                X509CertInfo info =
                                    thisreq.getExtDataInCertInfo(
                                            IEnrollProfile.REQUEST_CERTINFO);

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
                            LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditRequesterID,
                            auditProfileID(),
                            auditCertificateSubjectName);

                    audit(auditMessage);
                } catch (CertificateException e) {
                    CMS.debug("ConnectorServlet: processRequest "
                             + e.toString());

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditProfileID(),
                            auditCertificateSubjectName);

                    audit(auditMessage);
                } catch (IOException e) {
                    CMS.debug("ConnectorServlet: processRequest "
                             + e.toString());

                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_PROFILE_CERT_REQUEST,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditRequesterID,
                            auditProfileID(),
                            auditCertificateSubjectName);

                    audit(auditMessage);
                }
            }

            thisreq.setExtData(IRequest.AUTH_TOKEN, token);

            // setting requestor type must come after copy contents. because
            // requestor is a regular attribute.
            thisreq.setExtData(IRequest.REQUESTOR_TYPE,
                    IRequest.REQUESTOR_RA);
            mAuthority.log(ILogger.LL_INFO, "Processing remote request " +
                    srcid);

            // Set this so that request's updateBy is recorded
            SessionContext s = SessionContext.getContext();

            if (s.get(SessionContext.USER_ID) == null) {
                s.put(SessionContext.USER_ID, sourceUserId);
            }

            if (s.get(SessionContext.REQUESTER_ID) == null) {
                s.put(SessionContext.REQUESTER_ID, msg.getReqId());
            }

            CMS.debug("ConnectorServlet: calling processRequest instance=" +
                    thisreq);
            if (isProfileRequest(thisreq)) {
                normalizeProfileRequest(thisreq);
            }

            try {
                queue.processRequest(thisreq);

                if (isProfileRequest(thisreq)) {
                    // reset the "auditInfoCertValue"
                    auditInfoCertValue = auditInfoCertValue(thisreq);

                    if (auditInfoCertValue != null) {
                        if (!(auditInfoCertValue.equals(
                                   ILogger.SIGNED_AUDIT_EMPTY_VALUE))) {
                            // store a message in the signed audit log file
                            auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                    auditSubjectID,
                                    ILogger.SUCCESS,
                                    auditRequesterID,
                                    ILogger.SIGNED_AUDIT_ACCEPTANCE,
                                    auditInfoCertValue);

                            audit(auditMessage);
                        }
                    }
                }
            } catch (EBaseException eAudit1) {
                if (isProfileRequest(thisreq)) {
                    // reset the "auditInfoCertValue"
                    auditInfoCertValue = auditInfoCertValue(thisreq);

                    if (auditInfoCertValue != null) {
                        if (!(auditInfoCertValue.equals(
                                   ILogger.SIGNED_AUDIT_EMPTY_VALUE))) {
                            // store a message in the signed audit log file
                            auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_CERT_REQUEST_PROCESSED,
                                    auditSubjectID,
                                    ILogger.FAILURE,
                                    auditRequesterID,
                                    ILogger.SIGNED_AUDIT_ACCEPTANCE,
                                    auditInfoCertValue);

                            audit(auditMessage);
                        }
                    }
                }

                // rethrow EBaseException to primary catch clause
                // within this method
                throw eAudit1;
            }

            replymsg = CMS.getHttpPKIMessage();
            replymsg.fromRequest(thisreq);

            CMS.debug("ConnectorServlet: replymsg.reqStatus=" +
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
                CMS.debug("ConnectorServlet: done requestId=" +
                        thisreq.getRequestId().toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS,
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
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.FORMAT,
                                    new Object[] {
                                            thisreq.getRequestType(),
                                            thisreq.getRequestId(),
                                            initiative,
                                            authMgr,
                                            thisreq.getRequestStatus(),
                                            x509Info[i].get(X509CertInfo.SUBJECT),
                                            "" }
                                    );
                        }
                    } else {
                        mLogger.log(ILogger.EV_AUDIT,
                                ILogger.S_OTHER,
                                AuditFormat.LEVEL,
                                AuditFormat.NODNFORMAT,
                                new Object[] {
                                        thisreq.getRequestType(),
                                        thisreq.getRequestId(),
                                        initiative,
                                        authMgr,
                                        thisreq.getRequestStatus() }
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
                                mLogger.log(ILogger.EV_AUDIT,
                                        ILogger.S_OTHER,
                                        AuditFormat.LEVEL,
                                        AuditFormat.FORMAT,
                                        new Object[] {
                                                thisreq.getRequestType(),
                                                thisreq.getRequestId(),
                                                initiative,
                                                authMgr,
                                                "completed",
                                                x509Certs[i].getSubjectDN(),
                                                "cert issued serial number: 0x" +
                                                        x509Certs[i].getSerialNumber().toString(16) }
                                        );
                            }
                        } else {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.NODNFORMAT,
                                    new Object[] {
                                            thisreq.getRequestType(),
                                            thisreq.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "completed" }
                                    );
                        }
                    } else if (thisreq.getRequestType().equals(IRequest.RENEWAL_REQUEST)) {
                        X509CertImpl[] certs =
                                thisreq.getExtDataInCertArray(IRequest.OLD_CERTS);
                        X509CertImpl old_cert = certs[0];

                        certs = thisreq.getExtDataInCertArray(IRequest.ISSUED_CERTS);
                        X509CertImpl renewed_cert = certs[0];

                        if (old_cert != null && renewed_cert != null) {
                            mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.RENEWALFORMAT,
                                    new Object[] {
                                            thisreq.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "completed",
                                            old_cert.getSubjectDN(),
                                            old_cert.getSerialNumber().toString(16),
                                            "new serial number: 0x" +
                                                    renewed_cert.getSerialNumber().toString(16) }
                                    );
                        } else {
                            mLogger.log(ILogger.EV_AUDIT,
                                    ILogger.S_OTHER,
                                    AuditFormat.LEVEL,
                                    AuditFormat.NODNFORMAT,
                                    new Object[] {
                                            thisreq.getRequestType(),
                                            thisreq.getRequestId(),
                                            initiative,
                                            authMgr,
                                            "completed with error" }
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

                                                    mLogger.log(ILogger.EV_AUDIT,
                                                            ILogger.S_OTHER,
                                                            AuditFormat.LEVEL,
                                                            AuditFormat.DOREVOKEFORMAT,
                                                            new Object[] {
                                                                    thisreq.getRequestId(),
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
                        } else {
                            // the success.
                            for (int j = 0; j < count; j++) {
                                if (oldCerts[j] != null) {
                                    if (oldCerts[j] instanceof X509CertImpl) {
                                        X509CertImpl cert = (X509CertImpl) oldCerts[j];

                                        mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                                                AuditFormat.LEVEL,
                                                AuditFormat.DOREVOKEFORMAT,
                                                new Object[] {
                                                        thisreq.getRequestId(),
                                                        initiative,
                                                        "completed",
                                                        cert.getSubjectDN(),
                                                        cert.getSerialNumber().toString(16),
                                                        RevocationReason.fromInt(reason).toString() }
                                                );
                                    }
                                }
                            }
                        }
                    } else {
                        mLogger.log(ILogger.EV_AUDIT,
                                ILogger.S_OTHER,
                                AuditFormat.LEVEL,
                                AuditFormat.NODNFORMAT,
                                new Object[] {
                                        thisreq.getRequestType(),
                                        thisreq.getRequestId(),
                                        initiative,
                                        authMgr,
                                        "completed" }
                                );
                    }
                }

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS,
                            auditSubjectID,
                            ILogger.SUCCESS,
                            auditProtectionMethod,
                            auditRequestType,
                            auditRequesterID);

                audit(auditMessage);
            } catch (IOException e) {
                CMS.debug("ConnectorServlet: process " + e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProtectionMethod,
                            auditRequestType,
                            auditRequesterID);

                audit(auditMessage);
            } catch (CertificateException e) {
                CMS.debug("ConnectorServlet: process " + e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditProtectionMethod,
                            auditRequestType,
                            auditRequesterID);

                audit(auditMessage);
            } catch (Exception e) {
                CMS.debug("ConnectorServlet: process " + e.toString());

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS,
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
                        LOGGING_SIGNED_AUDIT_INTER_BOUNDARY_SUCCESS,
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
    protected void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (mSignedAuditLogger == null) {
            return;
        }

        mSignedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
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
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        String profileID = getId();

        if (profileID != null) {
            profileID = profileID.trim();
        } else {
            profileID = ILogger.UNIDENTIFIED;
        }

        return profileID;
    }

    /**
     * Signed Audit Log Info Certificate Value
     *
     * This method is called to obtain the certificate from the passed in
     * "X509CertImpl" for a signed audit log message.
     * <P>
     *
     * @param request a Request containing an X509CertImpl
     * @return cert string containing the certificate
     */
    private String auditInfoCertValue(IRequest request) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        X509CertImpl x509cert = request.getExtDataInCert(
                IEnrollProfile.REQUEST_ISSUED_CERT);

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

            StringBuffer sb = new StringBuffer();
            // extract all line separators from the "base64Data"
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
