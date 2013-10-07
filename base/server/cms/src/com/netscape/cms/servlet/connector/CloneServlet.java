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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.IAuthManager;
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
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;

/**
 * Clone servlet - part of the Clone Authority (CLA)
 * processes Revoked certs from its dependant clone CAs
 * service request and return status.
 *
 * @version $Revision$, $Date$
 */
public class CloneServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = -3474557834182380981L;
    public static final String INFO = "Clone Servlet";
    public final static String PROP_AUTHORITY = "authority";
    protected ServletConfig mConfig = null;
    protected IAuthority mAuthority = null;
    protected IRequestEncoder mReqEncoder = null;
    protected IAuthSubsystem mAuthSubsystem = null;
    protected ILogger mLogger = CMS.getLogger();

    public CloneServlet() {
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

    public void service(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException, IOException {
        boolean running_state = CMS.isInRunningState();

        if (!running_state)
            throw new IOException(
                    "CMS server is not ready to serve.");

        CMSRequest cmsRequest = newCMSRequest();

        // set argblock
        cmsRequest.setHttpParams(CMS.createArgBlock(toHashtable(req)));

        // set http request
        cmsRequest.setHttpReq(req);

        // set http response
        cmsRequest.setHttpResp(resp);

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
        len = req.getContentLength();

        // get content, a base 64 encoded serialized request.
        if (len > 0) {
            InputStream in = req.getInputStream();
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

        // force client auth handshake, validate clone CA (CCA)
        // and get CCA's Id.
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

        // authenticate clone CA (CCA)

        String CCA_Id = null;
        String CCAUserId = null;
        IAuthToken token = null;

        try {
            // cfu +++ authenticate checks both SUBJECT and Signer SUBJECT
            CMS.debug("CloneServlet: about to authenticate");
            token = authenticate(peerCert);
            // cfu maybe don't need CCA_Id, because the above check
            //			was good enough
            CCAUserId = token.getInString("userid");
            CCA_Id = peerCert.getSubjectDN().toString();
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
                "Clone Certificate Authority authenticated: " + peerCert.getSubjectDN());

        // authorize, any authenticated user are authorized
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

        // now process CCA request - should just be posting revoked
        //		certs for now

        try {
            // decode request.
            CMS.debug("Cloneservlet: before decoding request, encodedreq= " + encodedreq);
            msg = (IPKIMessage) mReqEncoder.decode(encodedreq);
            // process request
            CMS.debug("Cloneservlet: decoded request");
            replymsg = processRequest(CCA_Id, CCAUserId, msg, token);
        } catch (IOException e) {
            e.printStackTrace();
            mAuthority.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        } catch (EBaseException e) {
            mAuthority.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_IO_ERROR_REMOTE_REQUEST", e.toString()));
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        // encode reply
        String encodedrep = mReqEncoder.encode(replymsg);

        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("text/html");
        resp.setContentLength(encodedrep.length());

        // send reply
        OutputStream out = resp.getOutputStream();
        OutputStreamWriter writer = new OutputStreamWriter(out, "UTF8");

        writer.write(encodedrep);
        writer.flush();
        writer.close();
        out.flush();
    }

    //cfu ++change this to just check the subject and signer
    protected IAuthToken authenticate(
            X509Certificate peerCert)
            throws EBaseException {
        try {
            // XXX using agent authentication now since we're only
            // verifying that the cert belongs to a user in the db.
            // XXX change this to ACL in the future.

            // build JAVA X509Certificate from peerCert.
            X509CertImpl cert = new X509CertImpl(peerCert.getEncoded());

            AuthCredentials creds = new AuthCredentials();

            creds.set(IAuthManager.CRED_SSL_CLIENT_CERT,
                    new X509Certificate[] { cert }
                    );

            IAuthToken token = mAuthSubsystem.authenticate(creds,
                    IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            return token;
        } catch (CertificateException e) {
            mAuthority.log(ILogger.LL_SECURITY,
                    CMS.getLogMessage("CMSGW_REMOTE_AUTHORITY_AUTH_FAILURE", peerCert.getSubjectDN().toString()));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (EInvalidCredentials e) {
            mAuthority.log(ILogger.LL_SECURITY,
                    CMS.getLogMessage("CMSGW_REMOTE_AUTHORITY_AUTH_FAILURE", peerCert.getSubjectDN().toString()));
            throw e;
        } catch (EBaseException e) {
            mAuthority.log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_REMOTE_AUTHORITY_AUTH_FAILURE", peerCert.getSubjectDN().toString()));
            throw e;
        }
    }

    protected IPKIMessage processRequest(
            String source, String sourceUserId, IPKIMessage msg, IAuthToken token)
            throws EBaseException {
        IPKIMessage replymsg = null;
        IRequestQueue queue = mAuthority.getRequestQueue();
        String srcid = source + ":" + msg.getReqId();

        mAuthority.log(ILogger.LL_INFO, "CFU: in CloneServlet processRequest");

        // find request in request queue and return result.
        RequestId thisreqid = queue.findRequestBySourceId(srcid);
        IRequest thisreq = null;

        if (thisreqid != null) {
            thisreq = queue.findRequest(thisreqid);
            if (thisreq == null) {
                // strange case.
                String errormsg = "Cannot find request in request queue " + thisreqid;

                mAuthority.log(ILogger.LL_FAILURE, errormsg);
                throw new EBaseException(errormsg);
            } else {
                mAuthority.log(ILogger.LL_INFO,
                        "Found request " + thisreqid + " for " + srcid);
                replymsg = CMS.getHttpPKIMessage();
                replymsg.fromRequest(thisreq);
                return replymsg;
            }
        }

        // if not found process request.
        thisreq = queue.newRequest(msg.getReqType());
        thisreq.setSourceId(srcid);
        msg.toRequest(thisreq);
        thisreq.setExtData(IRequest.AUTH_TOKEN, token);

        // setting requestor type must come after copy contents. because
        // requestor is a regular attribute.
        thisreq.setExtData(IRequest.REQUESTOR_TYPE,
                IRequest.REQUESTOR_RA);
        mAuthority.log(ILogger.LL_INFO, "Processing remote request " + srcid);

        // Set this so that request's updateBy is recorded
        SessionContext s = SessionContext.getContext();

        if (s.get(SessionContext.USER_ID) == null) {
            s.put(SessionContext.USER_ID, sourceUserId);
        }

        queue.processRequest(thisreq);
        replymsg = CMS.getHttpPKIMessage();
        replymsg.fromRequest(thisreq);

        //for audit log
        String agentID = sourceUserId;
        String initiative = AuditFormat.FROMRA + " trustedManagerID: " +
                agentID + " remote reqID " + msg.getReqId();
        String authMgr = AuditFormat.NOAUTH;

        if (token != null) {
            authMgr =
                    token.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);
        }

        // Get the certificate info from the request
        X509CertInfo certInfo[] = thisreq.getExtDataInCertInfoArray(IRequest.CERT_INFO);

        try {
            if (!thisreq.getRequestStatus().equals(RequestStatus.COMPLETE)) {
                if (certInfo != null) {
                    for (int i = 0; i < certInfo.length; i++) {
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
                                        certInfo[i].get(X509CertInfo.SUBJECT),
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
                if (thisreq.getRequestType().equals(IRequest.CLA_CERT4CRL_REQUEST)) {
                    Integer result = thisreq.getExtDataInInteger(IRequest.RESULT);

                    if (result.equals(IRequest.RES_ERROR)) {
                        CMS.debug("CloneServlet: error in CLA_CERT4CRL_REQUEST");
                    } else {
                        // the success.
                        CMS.debug("CloneServlet: success in CLA_CERT4CRL_REQUEST");
                    }
                }

                /* cfu ---
                 if (thisreq.getRequestType().equals(IRequest.ENROLLMENT_REQUEST)) {
                 // XXX make the repeat record.
                // Get the certificate(s) from the request
                X509CertImpl issuedCerts[] =
                (X509CertImpl[])thisreq.get(IRequest.ISSUED_CERTS);
                // return potentially more than one certificates.
                if (issuedCerts != null) {
                for (int i = 0; i < issuedCerts.length; i++) {
                mLogger.log(ILogger.EV_AUDIT,
                ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.FORMAT,
                new Object[] {
                thisreq.getRequestType(),
                thisreq.getRequestId() ,
                initiative ,
                authMgr ,
                "completed",
                issuedCerts[i].getSubjectDN() ,
                "cert issued serial number: 0x" +
                issuedCerts[i].getSerialNumber().toString(16)}
                );
                }
                } else {
                mLogger.log(ILogger.EV_AUDIT,
                ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.NODNFORMAT,
                new Object[] {
                thisreq.getRequestType(),
                thisreq.getRequestId() ,
                initiative ,
                authMgr ,
                "completed"}
                );
                }
                } else if (thisreq.getRequestType().equals(IRequest.RENEWAL_REQUEST)) {
                X509CertImpl[] certs = (X509CertImpl[])thisreq.get(IRequest.OLD_CERTS);
                X509CertImpl old_cert = certs[0];
                certs = (X509CertImpl[])thisreq.get(IRequest.ISSUED_CERTS);
                X509CertImpl renewed_cert = certs[0];
                if (old_cert != null && renewed_cert != null) {
                mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.RENEWALFORMAT,
                new Object[] {
                thisreq.getRequestId(),
                initiative ,
                authMgr ,
                "completed",
                old_cert.getSubjectDN() ,
                old_cert.getSerialNumber().toString(16) ,
                "new serial number: 0x" +
                renewed_cert.getSerialNumber().toString(16)}
                );
                } else {
                mLogger.log(ILogger.EV_AUDIT,
                ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.NODNFORMAT,
                new Object[] {
                thisreq.getRequestType(),
                thisreq.getRequestId() ,
                initiative ,
                authMgr ,
                "completed with error"}
                );
                }
                } else if (thisreq.getRequestType().equals(IRequest.REVOCATION_REQUEST)) {
                X509CertImpl[] oldCerts = (X509CertImpl[])thisreq.get(IRequest.OLD_CERTS);
                RevokedCertImpl crlentries[] =
                (RevokedCertImpl[])thisreq.get(IRequest.REVOKED_CERTS);
                CRLExtensions crlExts = crlentries[0].getExtensions();
                int reason = 0;
                if (crlExts != null) {
                Enumeration enum = crlExts.getElements();
                while(enum.hasMoreElements()){
                Extension ext = (Extension) enum.nextElement();
                if (ext instanceof CRLReasonExtension) {
                reason = ((CRLReasonExtension)ext).getReason().toInt
                ();
                break;
                }
                }
                }

                int count = oldCerts.length;
                Integer result = (Integer)thisreq.get(IRequest.RESULT);
                if (result.equals(IRequest.RES_ERROR)) {
                EBaseException ex = (EBaseException)thisreq.get(IRequest.ERROR);
                EBaseException[] svcErrors =
                (EBaseException[])thisreq.get(IRequest.SVCERRORS);
                if (svcErrors != null && svcErrors.length > 0) {
                for (int i = 0; i < svcErrors.length; i++) {
                EBaseException err = svcErrors[i];
                if (err != null) {
                for (int j = 0; j < count; j++) {
                if (oldCerts[j] != null) {
                mLogger.log(ILogger.EV_AUDIT,
                ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.DOREVOKEFORMAT,
                new Object[] {
                thisreq.getRequestId(),
                initiative ,
                "completed with error: " +
                err.toString() ,
                oldCerts[j].getSubjectDN() ,
                oldCerts[j].getSerialNumber().toString(16),
                RevocationReason.fromInt(reason).toString()}
                );
                }
                }
                }
                }
                }
                } else {
                // the success.
                for (int j = 0; j < count; j++) {
                if (oldCerts[j] != null) {
                mLogger.log(ILogger.EV_AUDIT, ILogger.S_OTHER,
                AuditFormat.LEVEL,
                AuditFormat.DOREVOKEFORMAT,
                new Object[] {
                thisreq.getRequestId(),
                initiative ,
                "completed" ,
                oldCerts[j].getSubjectDN() ,
                oldCerts[j].getSerialNumber().toString(16),
                RevocationReason.fromInt(reason).toString()}
                );
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
                thisreq.getRequestId() ,
                initiative ,
                authMgr ,
                "completed"}
                );
                }
                cfu */
            }
        } catch (IOException e) {
        } catch (CertificateException e) {
        }

        return replymsg;
    }

    protected X509Certificate
            getPeerCert(HttpServletRequest req) throws EBaseException {
        return getSSLClientCertificate(req);
    }

    public String getServletInfo() {
        return INFO;
    }
}
