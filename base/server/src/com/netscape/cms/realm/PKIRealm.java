package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.catalina.realm.RealmBase;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.authentication.IAuthManager;
import org.dogtagpki.server.authentication.ICertUserDBAuthentication;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.IPasswdUserDBAuthentication;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.AuthEvent;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystem;

/**
 *  PKI Realm
 *
 *  This realm provides an authentication service against PKI user database.
 *  The realm also provides an authorization service that validates request
 *  URL's against the access control list defined in the internal database.
 */

public class PKIRealm extends RealmBase {

    private static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIRealm.class);

    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

    protected String getName() {
        return "PKIRealm";
    }

    @Override
    public Principal authenticate(String username, String password) {

        logger.info("PKIRealm: Authenticating user " + username + " with password");

        CMSEngine engine = CMS.getCMSEngine();
        String auditSubjectID = ILogger.UNIDENTIFIED;
        String attemptedAuditUID = username;

        try {
            AuthSubsystem authSub = engine.getAuthSubsystem();
            IAuthManager authMgr = authSub.getAuthManager(AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(IPasswdUserDBAuthentication.CRED_UID, username);
            creds.set(IPasswdUserDBAuthentication.CRED_PWD, password);

            IAuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(SessionContext.AUTH_MANAGER_ID, AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);
            auditSubjectID = authToken.getInString(IAuthToken.USER_ID);

            signedAuditLogger.log(AuthEvent.createSuccessEvent(
                        auditSubjectID,
                        AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID));

            return getPrincipal(username, authToken);

        } catch (EMissingCredential | EInvalidCredentials e) { // authentication failure

            logger.warn("Unable to authenticate user " + username + ": " + e.getMessage());

            signedAuditLogger.log(AuthEvent.createFailureEvent(
                        auditSubjectID,
                        AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID,
                        attemptedAuditUID));

            return null;

        } catch (Exception e) { // internal server error (e.g. LDAP exceptions)

            logger.warn("Unable to authenticate user " + username + ": " + e.getMessage(), e);

            signedAuditLogger.log(AuthEvent.createFailureEvent(
                        auditSubjectID,
                        AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID,
                        attemptedAuditUID));

            throw new RuntimeException(e);
        }
    }

    @Override
    public Principal authenticate(final X509Certificate[] certs) {

        logger.info("PKIRealm: Authenticating certificate chain:");

        for (int i=0; i<certs.length; i++) {
            X509Certificate cert = certs[i];
            logger.info("PKIRealm: - " + cert.getSubjectDN());
        }

        // get the cert from the ssl client auth
        // in cert based auth, subject id from cert has already passed SSL authentication
        // what remains is to see if the user exists in the internal user db
        // therefore both auditSubjectID and attemptedAuditUID are the same
        CMSEngine engine = CMS.getCMSEngine();
        String auditSubjectID = getAuditUserfromCert(certs[0]);
        String attemptedAuditUID = auditSubjectID;

        try {
            X509CertImpl certImpls[] = new X509CertImpl[certs.length];
            for (int i=0; i<certs.length; i++) {
                X509Certificate cert = certs[i];
                certImpls[i] = new X509CertImpl(cert.getEncoded());
            }

            AuthSubsystem authSub = engine.getAuthSubsystem();
            IAuthManager authMgr = authSub.getAuthManager(AuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(ICertUserDBAuthentication.CRED_CERT, certImpls);

            IAuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(SessionContext.AUTH_MANAGER_ID,AuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            String username = authToken.getInString(ICertUserDBAuthentication.TOKEN_USERID);
            // reset it to the one authenticated with authManager
            auditSubjectID = authToken.getInString(IAuthToken.USER_ID);

            logger.info("PKIRealm: User ID: " + username);

            signedAuditLogger.log(AuthEvent.createSuccessEvent(
                        auditSubjectID,
                        AuthSubsystem.CERTUSERDB_AUTHMGR_ID));

            return getPrincipal(username, authToken);

        } catch (EMissingCredential | EInvalidCredentials e) { // authentication failure

            logger.warn("Unable to authenticate cert chain: " + e.getMessage());

            signedAuditLogger.log(AuthEvent.createFailureEvent(
                    auditSubjectID,
                    AuthSubsystem.CERTUSERDB_AUTHMGR_ID,
                    attemptedAuditUID));

            return null;

        } catch (Exception e) { // internal server error (e.g. LDAP exceptions)

            logger.warn("Unable to authenticate cert chain: " + e.getMessage(), e);

            signedAuditLogger.log(AuthEvent.createFailureEvent(
                        auditSubjectID,
                        AuthSubsystem.CERTUSERDB_AUTHMGR_ID,
                        attemptedAuditUID));

            throw new RuntimeException(e);
        }
    }

    private String getAuditUserfromCert(X509Certificate clientCert) {
        String certUID = clientCert.getSubjectDN().getName();
        return StringUtils.stripToNull(certUID);
    }

    @Override
    protected Principal getPrincipal(String username) {

        logger.info("PKIRealm: Getting principal for " + username);

        try {
            return getPrincipal(username, (IAuthToken)null);

        } catch (Exception e) {
            logger.warn("Unable to get principal for " + username + ": " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    protected Principal getPrincipal(String username, IAuthToken authToken) throws Exception {
        IUser user = getUser(username);
        return getPrincipal(user, authToken);
    }

    protected Principal getPrincipal(IUser user, IAuthToken authToken) throws EUsrGrpException {
        List<String> roles = getRoles(user);
        return new PKIPrincipal(user, null, roles, authToken);
    }

    protected IUser getUser(String username) throws EUsrGrpException {
        CMSEngine engine = CMS.getCMSEngine();
        UGSubsystem ugSub = engine.getUGSubsystem();
        IUser user = ugSub.getUser(username);
        logger.info("PKIRealm: User DN: " + user.getUserDN());
        return user;
    }

    protected List<String> getRoles(IUser user) throws EUsrGrpException {

        List<String> roles = new ArrayList<String>();

        CMSEngine engine = CMS.getCMSEngine();
        UGSubsystem ugSub = engine.getUGSubsystem();
        Enumeration<IGroup> groups = ugSub.findGroupsByUser(user.getUserDN(), null);

        logger.info("PKIRealm: Roles:");
        while (groups.hasMoreElements()) {
            IGroup group = groups.nextElement();

            String name = group.getName();
            logger.info("PKIRealm: - " + name);
            roles.add(name);
        }

        return roles;
    }

    @Override
    protected String getPassword(String username) {
        return null;
    }
}
