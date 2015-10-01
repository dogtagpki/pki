package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.catalina.realm.RealmBase;
import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.ICertUserDBAuthentication;
import com.netscape.certsrv.authentication.IPasswdUserDBAuthentication;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.common.AuthCredentials;

import netscape.security.x509.X509CertImpl;

/**
 *  PKI Realm
 *
 *  This realm provides an authentication service against PKI user database.
 *  The realm also provides an authorization service that validates request
 *  URL's against the access control list defined in the internal database.
 */

public class PKIRealm extends RealmBase {
    protected ILogger signedAuditLogger = CMS.getSignedAuditLogger();
    private final static String LOGGING_SIGNED_AUDIT_AUTH_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTH_FAIL_4";
    private final static String LOGGING_SIGNED_AUDIT_AUTH_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTH_SUCCESS_3";

    @Override
    protected String getName() {
        return "PKIRealm";
    }

    @Override
    public Principal authenticate(String username, String password) {
        CMS.debug("PKIRealm: Authenticating user " + username + " with password.");
        String auditMessage = null;
        String auditSubjectID = ILogger.UNIDENTIFIED;
        String attemptedAuditUID = username;

        try {
            IAuthSubsystem authSub = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
            IAuthManager authMgr = authSub.getAuthManager(IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(IPasswdUserDBAuthentication.CRED_UID, username);
            creds.set(IPasswdUserDBAuthentication.CRED_PWD, password);

            IAuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(SessionContext.AUTH_MANAGER_ID, IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);
            auditSubjectID = authToken.getInString(IAuthToken.USER_ID);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTH_SUCCESS,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);

            audit(auditMessage);
            return getPrincipal(username, authToken);

        } catch (Throwable e) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID,
                        attemptedAuditUID);
            audit(auditMessage);
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public Principal authenticate(final X509Certificate certs[]) {
        CMS.debug("PKIRealm: Authenticating certificate chain:");

        String auditMessage = null;
        // get the cert from the ssl client auth
        // in cert based auth, subject id from cert has already passed SSL authentication
        // what remains is to see if the user exists in the internal user db
        // therefore both auditSubjectID and attemptedAuditUID are the same
        String auditSubjectID = getAuditUserfromCert(certs[0]);
        String attemptedAuditUID = auditSubjectID;

        try {
            X509CertImpl certImpls[] = new X509CertImpl[certs.length];
            for (int i=0; i<certs.length; i++) {
                X509Certificate cert = certs[i];
                CMS.debug("PKIRealm:   " + cert.getSubjectDN());

                // Convert sun.security.x509.X509CertImpl to netscape.security.x509.X509CertImpl
                certImpls[i] = new X509CertImpl(cert.getEncoded());
            }
            IAuthSubsystem authSub = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
            IAuthManager authMgr = authSub.getAuthManager(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(ICertUserDBAuthentication.CRED_CERT, certImpls);

            IAuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(SessionContext.AUTH_MANAGER_ID,IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            String username = authToken.getInString(ICertUserDBAuthentication.TOKEN_USERID);
            // reset it to the one authenticated with authManager
            auditSubjectID = authToken.getInString(IAuthToken.USER_ID);

            CMS.debug("PKIRealm: User ID: " + username);
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTH_SUCCESS,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            audit(auditMessage);
            return getPrincipal(username, authToken);

        } catch (Throwable e) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTH_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        IAuthSubsystem.CERTUSERDB_AUTHMGR_ID,
                        attemptedAuditUID);
            audit(auditMessage);
            e.printStackTrace();
        }

        return null;
    }

    private String getAuditUserfromCert(X509Certificate clientCert) {
        String certUID = clientCert.getSubjectDN().getName();
        CMS.debug("PKIRealm.getAuditUserfromCert: certUID=" + certUID);

        return StringUtils.stripToNull(certUID);
    }

    @Override
    protected Principal getPrincipal(String username) {
        return getPrincipal(username, (IAuthToken)null);
    }

    protected Principal getPrincipal(String username, IAuthToken authToken) {

        try {
            IUser user = getUser(username);
            return getPrincipal(user, authToken);

        } catch (Throwable e) {
            e.printStackTrace();
            return null;
        }
    }

    protected Principal getPrincipal(IUser user, IAuthToken authToken) throws EUsrGrpException {
        List<String> roles = getRoles(user);
        return new PKIPrincipal(user, null, roles, authToken);
    }

    protected IUser getUser(String username) throws EUsrGrpException {
        IUGSubsystem ugSub = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
        IUser user = ugSub.getUser(username);
        CMS.debug("PKIRealm: User DN: " + user.getUserDN());
        return user;
    }

    protected List<String> getRoles(IUser user) throws EUsrGrpException {

        List<String> roles = new ArrayList<String>();

        IUGSubsystem ugSub = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
        Enumeration<IGroup> groups = ugSub.findGroupsByUser(user.getUserDN(), null);

        CMS.debug("PKIRealm: Roles:");
        while (groups.hasMoreElements()) {
            IGroup group = groups.nextElement();

            String name = group.getName();
            CMS.debug("PKIRealm:   " + name);
            roles.add(name);
        }

        return roles;
    }

    @Override
    protected String getPassword(String username) {
        return null;
    }

    /**
     * Signed Audit Log
     *
     * This method is called to store messages to the signed audit log.
     * <P>
     *
     * @param msg signed audit log message
     */
    protected void audit(String msg) {
        // in this case, do NOT strip preceding/trailing whitespace
        // from passed-in String parameters

        if (signedAuditLogger == null) {
            return;
        }

        signedAuditLogger.log(ILogger.EV_SIGNED_AUDIT,
                null,
                ILogger.S_SIGNED_AUDIT,
                ILogger.LL_SECURITY,
                msg);
    }
}
