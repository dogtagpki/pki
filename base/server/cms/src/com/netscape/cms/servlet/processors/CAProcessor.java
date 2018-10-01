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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.processors;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.StringTokenizer;

import javax.servlet.http.HttpServletRequest;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EAuthException;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.AuthEvent;
import com.netscape.certsrv.logging.event.AuthzEvent;
import com.netscape.certsrv.logging.event.RoleAssumeEvent;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.usrgrp.ICertUserLocator;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.util.IStatsSubsystem;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cms.servlet.common.CMSGateway;
import com.netscape.cms.servlet.common.ServletUtils;

import netscape.security.x509.X509CertImpl;

public class CAProcessor extends Processor {

    public final static String ARG_REQUEST_OWNER = "requestOwner";
    public final static String HDR_LANG = "accept-language";
    public final static String ARG_PROFILE = "profile";
    public final static String ARG_REQUEST_NOTES = "requestNotes";
    public final static String ARG_RENEWAL_PROFILE_ID = "rprofileId";
    public final static String ARG_PROFILE_IS_ENABLED = "profileIsEnable";
    public final static String ARG_PROFILE_IS_VISIBLE = "profileIsVisible";
    public final static String ARG_PROFILE_ENABLED_BY = "profileEnableBy";
    public final static String ARG_PROFILE_APPROVED_BY = "profileApprovedBy";
    public final static String ARG_PROFILE_NAME = "profileName";
    public final static String ARG_PROFILE_DESC = "profileDesc";
    public final static String ARG_PROFILE_REMOTE_HOST = "profileRemoteHost";
    public final static String ARG_PROFILE_REMOTE_ADDR = "profileRemoteAddr";
    public final static String ARG_PROFILE_SET_ID = "profileSetId";
    public final static String ARG_OUTPUT_LIST = "outputList";
    public final static String ARG_OUTPUT_ID = "outputId";
    public final static String ARG_OUTPUT_SYNTAX = "outputSyntax";
    public final static String ARG_OUTPUT_CONSTRAINT = "outputConstraint";
    public final static String ARG_OUTPUT_NAME = "outputName";
    public final static String ARG_OUTPUT_VAL = "outputVal";
    public final static String ARG_REQUEST_LIST = "requestList";
    public final static String ARG_REQUEST_ID = "requestId";
    public final static String ARG_REQUEST_TYPE = "requestType";
    public final static String ARG_REQUEST_STATUS = "requestStatus";
    public final static String ARG_REQUEST_CREATION_TIME = "requestCreationTime";
    public final static String ARG_REQUEST_MODIFICATION_TIME = "requestModificationTime";
    public final static String ARG_REQUEST_NONCE = "nonce";
    public final static String ARG_OP = "op";
    public final static String ARG_REQUESTS = "requests";
    public final static String ARG_ERROR_CODE = "errorCode";
    public final static String ARG_ERROR_REASON = "errorReason";
    public final static String CERT_ATTR = "javax.servlet.request.X509Certificate";

    // servlet config constants
    public static final String PROFILE_ID = "profileId";
    public static final String AUTH_ID = "authId";
    public static final String ACL_METHOD = "aclMethod";
    public static final String AUTHZ_RESOURCE_NAME = "authzResourceName";
    public static final String AUTH_MGR = "authMgr";
    public static final String AUTHZ_MGR = "authzMgr";
    public static final String GET_CLIENT_CERT = "getClientCert";
    public static final String ACL_INFO = "ACLinfo";
    public static final String PROFILE_SUB_ID = "profileSubId";

    protected String profileID;
    protected String profileSubId;
    protected String aclMethod;
    protected String authzResourceName;
    protected String authMgr;
    protected String getClientCert = "false";
    // subsystems
    protected ICertificateAuthority authority = (ICertificateAuthority) CMS.getSubsystem("ca");
    protected IAuthzSubsystem authz = (IAuthzSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTHZ);
    protected IUGSubsystem ug = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
    protected ICertUserLocator ul = ug.getCertUserLocator();
    protected IRequestQueue queue;
    protected IProfileSubsystem ps;
    protected ICertificateRepository certdb;

    //logging and stats

    protected LinkedHashSet<String> statEvents = new LinkedHashSet<String>();

    public CAProcessor(String id, Locale locale) throws EPropertyNotFound, EBaseException {
        super(id, locale);

        IConfigStore cs = CMS.getConfigStore().getSubStore("processor." + id);
        this.profileID = cs.getString(PROFILE_ID, "").isEmpty() ? null : cs.getString(PROFILE_ID);
        this.authzResourceName = cs.getString(AUTHZ_RESOURCE_NAME, "").isEmpty() ? null :
            cs.getString(AUTHZ_RESOURCE_NAME);
        this.authMgr = cs.getString(AUTH_MGR, "").isEmpty() ? null : cs.getString(AUTH_MGR);
        this.getClientCert = cs.getString(GET_CLIENT_CERT, "").isEmpty() ? "false" : cs.getString(GET_CLIENT_CERT);
        this.profileSubId = cs.getString(PROFILE_SUB_ID, "").isEmpty() ? IProfileSubsystem.ID :
            cs.getString(PROFILE_SUB_ID);

        String aclInfo = cs.getString(ACL_INFO, "").isEmpty() ? null : cs.getString(ACL_INFO);
        String authzMgr = cs.getString(AUTHZ_MGR, "").isEmpty() ? null : cs.getString(AUTHZ_MGR);
        this.aclMethod = ServletUtils.getACLMethod(aclInfo, authzMgr, id);

        // currently unused but in servlet config
        // authId = cs.getString(AUTH_ID, "").isEmpty() ? null : cs.getString(AUTH_ID);

        if (authority == null) {
            throw new EBaseException("CAProcessor: authority is null");
        }

        queue = authority.getRequestQueue();
        if (queue == null) {
            throw new EBaseException("CAProcessor: cannot get request queue");
        }

        if (profileSubId == null || profileSubId.equals("")) {
            profileSubId = IProfileSubsystem.ID;
        }

        ps = (IProfileSubsystem) CMS.getSubsystem(profileSubId);
        if (ps == null) {
            throw new EBaseException("CAProcessor: Profile Subsystem not found");
        }

        certdb = authority.getCertificateRepository();
        if (certdb == null) {
            throw new EBaseException("CAProcessor: Certificate repository not found");
        }
    }

    public String getProfileID() {
        return profileID;
    }

    public IProfileSubsystem getProfileSubsystem() {
        return ps;
    }

    /******************************************
     * Stats - to be moved to Stats module
     ******************************************/

    public void startTiming(String event) {
        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.startTiming(event, true);
        }
        statEvents.add(event);
    }

    public void endTiming(String event) {
        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            statsSub.endTiming(event);
        }
        statEvents.remove(event);
    }

    public void endAllEvents() {
        IStatsSubsystem statsSub = (IStatsSubsystem) CMS.getSubsystem("stats");
        if (statsSub != null) {
            Iterator<String> iter = statEvents.iterator();
            while (iter.hasNext()) {
                String event = iter.next();
                statsSub.endTiming(event);
                iter.remove();
            }
        }
    }

    /******************************************
     * Utility Functions
     ******************************************/

    public IRequest getRequest(String rid) throws EBaseException {
        IRequest request = queue.findRequest(new RequestId(rid));
        return request;
    }

    protected IRequest getOriginalRequest(BigInteger certSerial, ICertRecord rec) throws EBaseException {
        MetaInfo metaInfo = (MetaInfo) rec.get(ICertRecord.ATTR_META_INFO);
        if (metaInfo == null) {
            CMS.debug("getOriginalRequest: cert record locating MetaInfo failed for serial number "
                    + certSerial.toString());
            return null;
        }

        String rid = (String) metaInfo.get(ICertRecord.META_REQUEST_ID);
        if (rid == null) {
            CMS.debug("getOriginalRequest: cert record locating request id in MetaInfo failed " +
                    "for serial number " + certSerial.toString());
            return null;
        }

        IRequest request = queue.findRequest(new RequestId(rid));
        return request;
    }

    protected void printParameterValues(HashMap<String, String> data) {

        CMS.debug("CAProcessor: Input Parameters:");

        for (Entry<String, String> entry : data.entrySet()) {
            String paramName = entry.getKey();
            // added this facility so that password can be hidden,
            // all sensitive parameters should be prefixed with
            // __ (double underscores); however, in the event that
            // a security parameter slips through, we perform multiple
            // additional checks to insure that it is NOT displayed
            if (CMS.isSensitive(paramName)) {
                CMS.debug("CAProcessor: - " + paramName + ": (sensitive)");
            } else {
                CMS.debug("CAProcessor: - " + paramName + ": " + entry.getValue());
            }
        }
    }

    /**
     * get ssl client authenticated certificate
     */
    public static X509Certificate getSSLClientCertificate(HttpServletRequest httpReq)
            throws EBaseException {
        X509Certificate cert = null;

        CMS.debug(CMS.getLogMessage("CMSGW_GETTING_SSL_CLIENT_CERT"));

        // iws60 support Java Servlet Spec V2.2, attribute
        // javax.servlet.request.X509Certificate now contains array
        // of X509Certificates instead of one X509Certificate object
        X509Certificate[] allCerts = (X509Certificate[]) httpReq.getAttribute(CERT_ATTR);

        if (allCerts == null || allCerts.length == 0) {
            throw new EBaseException("You did not provide a valid certificate for this operation");
        }

        cert = allCerts[0];

        if (cert == null) {
            // just don't have a cert.

            CMS.debug(CMS.getLogMessage("CMSGW_SSL_CL_CERT_FAIL"));
            return null;
        }

        // convert to sun's x509 cert interface.
        try {
            byte[] certEncoded = cert.getEncoded();
            cert = new X509CertImpl(certEncoded);
        } catch (CertificateEncodingException e) {
            CMS.debug(CMS.getLogMessage("CMSGW_SSL_CL_CERT_FAIL_ENCODE", e.getMessage()));
            return null;

        } catch (CertificateException e) {
            CMS.debug(CMS.getLogMessage("CMSGW_SSL_CL_CERT_FAIL_DECODE", e.getMessage()));
            return null;
        }
        return cert;
    }

    protected static Hashtable<String, String> toHashtable(HttpServletRequest req) {
        Hashtable<String, String> httpReqHash = new Hashtable<String, String>();
        Enumeration<?> names = req.getParameterNames();

        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();

            httpReqHash.put(name, req.getParameter(name));
        }
        return httpReqHash;
    }

    /******************************************
     * AUTHENTICATION FUNCTIONS (move to Realm?)
     ******************************************/

    /*
     *   authenticate for renewal - more to add necessary params/values
     *   to the session context
     */
    public IAuthToken authenticate(
            IProfileAuthenticator authenticator,
            HttpServletRequest request,
            IRequest origReq,
            SessionContext context,
            AuthCredentials credentials) throws EBaseException
    {
        IAuthToken authToken = authenticate(authenticator, request, credentials);
        // For renewal, fill in necessary params
        if (authToken != null) {
            String ouid = origReq.getExtDataInString("auth_token.uid");
            // if the orig cert was manually approved, then there was
            // no auth token uid.  Try to get the uid from the cert dn
            // itself, if possible
            if (ouid == null) {
                String sdn = (String) context.get("origSubjectDN");
                if (sdn != null) {
                    ouid = getUidFromDN(sdn);
                    if (ouid != null)
                        CMS.debug("CAProcessor: renewal: authToken original uid not found");
                }
            } else {
                CMS.debug("CAProcessor: renewal: authToken original uid found in orig request auth_token");
            }
            String auid = authToken.getInString("uid");
            if (auid != null) { // not through ssl client auth
                CMS.debug("CAProcessor: renewal: authToken uid found:" + auid);
                // authenticated with uid
                // put "orig_req.auth_token.uid" so that authz with
                // UserOrigReqAccessEvaluator will work
                if (ouid != null) {
                    context.put("orig_req.auth_token.uid", ouid);
                    CMS.debug("CAProcessor: renewal: authToken original uid found:" + ouid);
                } else {
                    CMS.debug("CAProcessor: renewal: authToken original uid not found");
                }
            } else { // through ssl client auth?
                CMS.debug("CAProcessor: renewal: authToken uid not found:");
                // put in orig_req's uid
                if (ouid != null) {
                    CMS.debug("CAProcessor: renewal: origReq uid not null:" + ouid + ". Setting authtoken");
                    authToken.set("uid", ouid);
                    context.put(SessionContext.USER_ID, ouid);
                } else {
                    CMS.debug("CAProcessor: renewal: origReq uid not found");
                    //                      throw new EBaseException("origReq uid not found");
                }
            }

            String userdn = origReq.getExtDataInString("auth_token.userdn");
            if (userdn != null) {
                CMS.debug("CAProcessor: renewal: origReq userdn not null:" + userdn + ". Setting authtoken");
                authToken.set("userdn", userdn);
            } else {
                CMS.debug("CAProcessor: renewal: origReq userdn not found");
                //                      throw new EBaseException("origReq userdn not found");
            }
        } else {
            CMS.debug("CAProcessor: renewal: authToken null");
        }
        return authToken;
    }

    public IAuthToken authenticate(
            IProfileAuthenticator authenticator,
            HttpServletRequest request,
            AuthCredentials credentials) throws EBaseException {

        if (credentials == null) {
            credentials = new AuthCredentials();

            // build credential
            Enumeration<String> authNames = authenticator.getValueNames();

            if (authNames != null) {
                while (authNames.hasMoreElements()) {
                    String authName = authNames.nextElement();

                    credentials.set(authName, request.getParameter(authName));
                }
            }
        }

        credentials.set("clientHost", request.getRemoteHost());
        IAuthToken authToken = authenticator.authenticate(credentials);

        SessionContext sc = SessionContext.getContext();
        if (sc != null) {
            sc.put(SessionContext.AUTH_MANAGER_ID, authenticator.getName());
            String userid = authToken.getInString(IAuthToken.USER_ID);
            if (userid != null) {
                sc.put(SessionContext.USER_ID, userid);
            }
        }

        return authToken;
    }

    public IAuthToken authenticate(
            HttpServletRequest request,
            IRequest origReq,
            IProfileAuthenticator authenticator,
            SessionContext context,
            boolean isRenewal,
            AuthCredentials credentials) throws EBaseException {
        startTiming("profile_authentication");

        IAuthToken authToken = null;
        if (authenticator != null) {
            CMS.debug("authenticate: authentication required.");
            String uid_cred = "Unidentified";
            String uid_attempted_cred = "Unidentified";
            Enumeration<String> authIds = authenticator.getValueNames();
            //Attempt to possibly fetch attempted uid, may not always be available.
            if (authIds != null) {
                while (authIds.hasMoreElements()) {
                    String authName = authIds.nextElement();
                    String value = request.getParameter(authName);
                    if (value != null) {
                        if (authName.equals("uid")) {
                            uid_attempted_cred = value;
                        }
                    }
                }
            }

            String authSubjectID = auditSubjectID();
            String authMgrID = authenticator.getName();

            try {
                if (isRenewal) {
                    authToken = authenticate(authenticator, request, origReq, context, credentials);
                } else {
                    authToken = authenticate(authenticator, request, credentials);
                }

            } catch (EAuthException e) {
                CMS.debug("CAProcessor: authentication error: " + e);

                authSubjectID += " : " + uid_cred;

                signedAuditLogger.log(AuthEvent.createFailureEvent(
                        authSubjectID,
                        authMgrID,
                        uid_attempted_cred));

                throw e;

            } catch (EBaseException e) {
                CMS.debug(e);

                authSubjectID += " : " + uid_cred;

                signedAuditLogger.log(AuthEvent.createFailureEvent(
                        authSubjectID,
                        authMgrID,
                        uid_attempted_cred));

                throw e;
            }

            //Log successful authentication
            //Attempt to get uid from authToken, most tokens respond to the "uid" cred.
            uid_cred = authToken.getInString("uid");

            if (uid_cred == null || uid_cred.length() == 0) {
                uid_cred = "Unidentified";
            }

            authSubjectID = authSubjectID + " : " + uid_cred;

            signedAuditLogger.log(AuthEvent.createSuccessEvent(
                    authSubjectID,
                    authMgrID));
        }
        endTiming("profile_authentication");
        return authToken;
    }

    public IAuthToken authenticate(HttpServletRequest httpReq)
            throws EBaseException {
        return authenticate(httpReq, authMgr);
    }

    public static void saveAuthToken(IAuthToken token, IRequest req) {
        if (token != null && req != null)
            req.setExtData(IRequest.AUTH_TOKEN, token);

        // # 56230 - expose auth token parameters to the policy predicate
        if (token != null && req != null) {
            Enumeration<String> e = token.getElements();
            while (e.hasMoreElements()) {
                String n = e.nextElement();
                String[] x1 = token.getInStringArray(n);
                if (x1 != null) {
                    for (int i = 0; i < x1.length; i++) {
                        CMS.debug("Setting " + IRequest.AUTH_TOKEN + "-" + n +
                                "(" + i + ")=" + x1[i]);
                        req.setExtData(IRequest.AUTH_TOKEN + "-" + n + "(" + i + ")",
                                x1[i]);
                    }
                } else {
                    String x = token.getInString(n);
                    if (x != null) {
                        CMS.debug("Setting " + IRequest.AUTH_TOKEN + "-" + n + "=" + x);
                        req.setExtData(IRequest.AUTH_TOKEN + "-" + n, x);
                    }
                }
            } // while
        } // if
    }

    public IAuthToken authenticate(HttpServletRequest httpReq, String authMgrName)
            throws EBaseException {

        String auditSubjectID = ILogger.UNIDENTIFIED;
        String auditAuthMgrID = ILogger.UNIDENTIFIED;
        String auditUID = ILogger.UNIDENTIFIED;

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            IArgBlock httpArgs = CMS.createArgBlock(toHashtable(httpReq));
            SessionContext ctx = SessionContext.getContext();
            String ip = httpReq.getRemoteAddr();
            CMS.debug("IP: " + ip);

            if (ip != null) {
                ctx.put(SessionContext.IPADDRESS, ip);
            }
            if (authMgrName != null) {
                CMS.debug("AuthMgrName: " + authMgrName);
                ctx.put(SessionContext.AUTH_MANAGER_ID, authMgrName);
            }
            // put locale into session context
            ctx.put(SessionContext.LOCALE, locale);

            //
            // check ssl client authentication if specified.
            //
            X509Certificate clientCert = null;

            if (getClientCert != null && getClientCert.equals("true")) {
                CMS.debug("CMSServlet: retrieving SSL certificate");
                clientCert = getSSLClientCertificate(httpReq);
            }

            //
            // check authentication by auth manager if any.
            //
            if (authMgrName == null) {

                // Fixed Blackflag Bug #613900:  Since this code block does
                // NOT actually constitute an authentication failure, but
                // rather the case in which a given servlet has been correctly
                // configured to NOT require an authentication manager, the
                // audit message called LOGGING_SIGNED_AUDIT_AUTH_FAIL has
                // been removed.

                CMS.debug("CMSServlet: no authMgrName");
                return null;
            } else {
                // save the "Subject DN" of this certificate in case it
                // must be audited as an authentication failure
                if (clientCert == null) {
                    CMS.debug("CMSServlet: no client certificate found");
                } else {
                    String certUID = clientCert.getSubjectDN().getName();
                    CMS.debug("CMSServlet: certUID=" + certUID);

                    if (certUID != null) {
                        certUID = certUID.trim();

                        if (!(certUID.equals(""))) {
                            // reset the "auditUID"
                            auditUID = certUID;
                        }
                    }
                }

                // reset the "auditAuthMgrID"
                auditAuthMgrID = authMgrName;
            }
            AuthToken authToken = CMSGateway.checkAuthManager(httpReq,
                    httpArgs,
                    clientCert,
                    authMgrName);
            if (authToken == null) {
                return null;
            }
            String userid = authToken.getInString(IAuthToken.USER_ID);

            CMS.debug("CMSServlet: userid=" + userid);

            if (userid != null) {
                ctx.put(SessionContext.USER_ID, userid);
            }

            // reset the "auditSubjectID"
            auditSubjectID = auditSubjectID();

            signedAuditLogger.log(AuthEvent.createSuccessEvent(
                    auditSubjectID,
                    auditAuthMgrID));

            return authToken;
        } catch (EBaseException eAudit1) {

            signedAuditLogger.log(AuthEvent.createFailureEvent(
                    auditSubjectID,
                    auditAuthMgrID,
                    auditUID));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        }
    }

    String getUidFromDN(String userdn) {
        StringTokenizer st = new StringTokenizer(userdn, ",");
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            int i = t.indexOf("=");

            if (i == -1) {
                continue;
            }
            String n = t.substring(0, i);
            if (n.equalsIgnoreCase("uid")) {
                String v = t.substring(i + 1);
                CMS.debug("CAProcessor:: getUidFromDN(): uid found:" + v);
                return v;
            } else {
                continue;
            }
        }
        return null;
    }

    /******************************************
     * AUTHZ FNCTIONS (to be moved to Realm?)
     *****************************************/

    public AuthzToken authorize(String authzMgrName, String resource, IAuthToken authToken,
            String exp) throws EBaseException {
        AuthzToken authzToken = null;

        CMS.debug("CAProcessor.authorize(" + authzMgrName + ", " + resource + ")");

        String auditSubjectID = auditSubjectID();
        String auditGroupID = auditGroupID();
        String auditACLResource = resource;
        String auditOperation = "enroll";

        try {
            authzToken = authz.authorize(authzMgrName, authToken, exp);
            if (authzToken != null) {

                signedAuditLogger.log(AuthzEvent.createSuccessEvent(
                        auditSubjectID,
                        auditACLResource,
                        auditOperation));

                signedAuditLogger.log(RoleAssumeEvent.createSuccessEvent(
                        auditSubjectID,
                        auditGroupID));

            } else {

                signedAuditLogger.log(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        auditACLResource,
                        auditOperation));

                signedAuditLogger.log(RoleAssumeEvent.createFailureEvent(
                        auditSubjectID,
                        auditGroupID));
            }
            return authzToken;
        } catch (EBaseException e) {

            signedAuditLogger.log(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    auditACLResource,
                    auditOperation));

            signedAuditLogger.log(RoleAssumeEvent.createFailureEvent(
                    auditSubjectID,
                    auditGroupID));

            throw e;
        }
    }

    /**
     * Authorize must occur after Authenticate
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTHZ_FAIL used when authorization has failed
     * <li>signed.audit LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS used when authorization is successful
     * <li>signed.audit LOGGING_SIGNED_AUDIT_ROLE_ASSUME used when user assumes a role (in current CS that's when one
     * accesses a role port)
     * </ul>
     *
     * @param authzMgrName string representing the name of the authorization
     *            manager
     * @param authToken the authentication token
     * @param resource a string representing the ACL resource id as defined in
     *            the ACL resource list
     * @param operation a string representing one of the operations as defined
     *            within the ACL statement (e. g. - "read" for an ACL statement containing
     *            "(read,write)")
     * @exception EBaseException an error has occurred
     * @return the authorization token
     */
    public AuthzToken authorize(String authzMgrName, IAuthToken authToken,
            String resource, String operation) {

        CMS.debug("CAProcessor.authorize(" + authzMgrName + ")");

        String auditSubjectID = auditSubjectID();
        String auditGroupID = auditGroupID();
        String auditID = auditSubjectID;
        String auditACLResource = resource;
        String auditOperation = operation;

        SessionContext auditContext = SessionContext.getExistingContext();
        String authManagerId = null;

        if (auditContext != null) {
            authManagerId = (String) auditContext.get(SessionContext.AUTH_MANAGER_ID);

            if (authManagerId != null && authManagerId.equals("TokenAuth")) {
                if (auditSubjectID.equals(ILogger.NONROLEUSER) ||
                        auditSubjectID.equals(ILogger.UNIDENTIFIED)) {
                    CMS.debug("CMSServlet: in authorize... TokenAuth auditSubjectID unavailable, changing to auditGroupID");
                    auditID = auditGroupID;
                }
            }
        }

        // "normalize" the "auditACLResource" value
        if (auditACLResource != null) {
            auditACLResource = auditACLResource.trim();
        }

        // "normalize" the "auditOperation" value
        if (auditOperation != null) {
            auditOperation = auditOperation.trim();
        }

        if (authzMgrName == null) {
            // Fixed Blackflag Bug #613900:  Since this code block does
            // NOT actually constitute an authorization failure, but
            // rather the case in which a given servlet has been correctly
            // configured to NOT require an authorization manager, the
            // audit message called LOGGING_SIGNED_AUDIT_AUTHZ_FAIL and
            // the audit message called LOGGING_SIGNED_AUDIT_ROLE_ASSUME
            // (marked as a failure) have been removed.

            return null;
        }

        String roles = auditGroups(auditSubjectID);

        try {
            AuthzToken authzTok = authz.authorize(authzMgrName,
                    authToken,
                    resource,
                    operation);

            if (authzTok != null) {

                signedAuditLogger.log(AuthzEvent.createSuccessEvent(
                        auditSubjectID,
                        auditACLResource,
                        auditOperation));

                if (roles != null) {
                    signedAuditLogger.log(RoleAssumeEvent.createSuccessEvent(
                            auditID,
                            roles));
                }

            } else {

                signedAuditLogger.log(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        auditACLResource,
                        auditOperation));

                if (roles != null) {
                    signedAuditLogger.log(RoleAssumeEvent.createFailureEvent(
                            auditID,
                            roles));
                }
            }

            return authzTok;
        } catch (Exception eAudit1) {

            signedAuditLogger.log(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    auditACLResource,
                    auditOperation));

            if (roles != null) {
                signedAuditLogger.log(RoleAssumeEvent.createFailureEvent(
                        auditID,
                        roles));
            }

            return null;
        }
    }

    public void authorize(String profileId, IProfile profile, IAuthToken authToken) throws EBaseException {
        if (authToken != null) {
            CMS.debug("CertProcessor authToken not null");

            String acl = profile.getAuthzAcl();
            CMS.debug("CAProcessor: authz using acl: " + acl);
            if (acl != null && acl.length() > 0) {
                String resource = profileId + ".authz.acl";
                authorize(aclMethod, resource, authToken, acl);
            }
        }
    }

    /**
     * Signed Audit Log Requester ID
     *
     * This method is called to obtain the "RequesterID" for
     * a signed audit log message.
     * <P>
     *
     * @param request the actual request
     * @return id string containing the signed audit log message RequesterID
     */
    protected String auditRequesterID(IRequest request) {

        String requesterID = ILogger.UNIDENTIFIED;

        if (request != null) {
            // overwrite "requesterID" if and only if "id" != null
            String id = request.getRequestId().toString();

            if (id != null) {
                requesterID = id.trim();
            }
        }

        return requesterID;
    }

    protected String auditSubjectID() {

        CMS.debug("CMSServlet: in auditSubjectID");
        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        CMS.debug("CMSServlet: auditSubjectID auditContext " + auditContext);
        if (auditContext != null) {
            subjectID = (String)
                    auditContext.get(SessionContext.USER_ID);

            CMS.debug("CMSServlet auditSubjectID: subjectID: " + subjectID);
            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }

    protected String auditGroupID() {

        CMS.debug("CMSServlet: in auditGroupID");
        String groupID = null;

        // Initialize groupID
        SessionContext auditContext = SessionContext.getExistingContext();

        CMS.debug("CMSServlet: auditGroupID auditContext " + auditContext);
        if (auditContext != null) {
            groupID = (String)
                    auditContext.get(SessionContext.GROUP_ID);

            CMS.debug("CMSServlet auditGroupID: groupID: " + groupID);
            if (groupID != null) {
                groupID = groupID.trim();
            } else {
                groupID = ILogger.NONROLEUSER;
            }
        } else {
            groupID = ILogger.UNIDENTIFIED;
        }

        return groupID;
    }

    /**
     * Signed Audit Groups
     *
     * This method is called to extract all "groups" associated
     * with the "auditSubjectID()".
     * <P>
     *
     * @param SubjectID string containing the signed audit log message SubjectID
     * @return a delimited string of groups associated
     *         with the "auditSubjectID()"
     */
    protected String auditGroups(String SubjectID) {

        if (SubjectID == null || SubjectID.equals(ILogger.UNIDENTIFIED)) {
            return null;
        }

        Enumeration<IGroup> groups = null;

        try {
            groups = ug.findGroups("*");
        } catch (Exception e) {
            return null;
        }

        StringBuffer membersString = new StringBuffer();

        while (groups.hasMoreElements()) {
            IGroup group = groups.nextElement();

            if (group.isMember(SubjectID) == true) {
                if (membersString.length() != 0) {
                    membersString.append(", ");
                }

                membersString.append(group.getGroupID());
            }
        }

        if (membersString.length() == 0) {
            return null;
        }

        return membersString.toString();
    }

    public void validateNonce(
            HttpServletRequest servletRequest,
            String name,
            Object id,
            Long nonce) throws EBaseException {

        if (nonce == null) {
            throw new BadRequestException("Missing nonce.");
        }

        Map<Object, Long> nonces = authority.getNonces(servletRequest, name);

        Long storedNonce = nonces.get(id);
        if (storedNonce == null) {
            throw new BadRequestException("Nonce for "+name+" "+id+" does not exist.");
        }

        if (!nonce.equals(storedNonce)) {
            throw new ForbiddenException("Invalid nonce");
        }

        nonces.remove(id);

        CMS.debug("Processor: Nonce verified");
    }
}
