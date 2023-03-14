package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.catalina.realm.RealmBase;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IPasswdUserDBAuthentication;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.AuthEvent;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.authentication.CertUserDBAuthentication;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

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

    protected CMSEngine engine;

    public PKIRealm() {
    }

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    protected String getName() {
        return "PKIRealm";
    }

    @Override
    public Principal authenticate(String username, String password) {

        logger.info("PKIRealm: Authenticating user " + username + " with password");

        String auditSubjectID = ILogger.UNIDENTIFIED;
        String attemptedAuditUID = username;

        try {
            AuthSubsystem authSub = engine.getAuthSubsystem();
            AuthManager authMgr = authSub.getAuthManager(AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(IPasswdUserDBAuthentication.CRED_UID, username);
            creds.set(IPasswdUserDBAuthentication.CRED_PWD, password);

            AuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(SessionContext.AUTH_MANAGER_ID, AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);
            auditSubjectID = authToken.getInString(AuthToken.USER_ID);

            logger.info("PKIRealm: User " + username + " authenticated");

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
        String auditSubjectID = getAuditUserfromCert(certs[0]);
        String attemptedAuditUID = auditSubjectID;

        try {
            X509CertImpl certImpls[] = new X509CertImpl[certs.length];
            for (int i=0; i<certs.length; i++) {
                X509Certificate cert = certs[i];
                certImpls[i] = new X509CertImpl(cert.getEncoded());
            }

            AuthSubsystem authSub = engine.getAuthSubsystem();
            AuthManager authMgr = authSub.getAuthManager(AuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(CertUserDBAuthentication.CRED_CERT, certImpls);

            AuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(SessionContext.AUTH_MANAGER_ID,AuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            String username = authToken.getInString(CertUserDBAuthentication.TOKEN_USERID);
            // reset it to the one authenticated with authManager
            auditSubjectID = authToken.getInString(AuthToken.USER_ID);

            logger.info("PKIRealm: User " + username + " authenticated");

            signedAuditLogger.log(AuthEvent.createSuccessEvent(
                        auditSubjectID,
                        AuthSubsystem.CERTUSERDB_AUTHMGR_ID));

            return getPrincipal(username, authToken);

        } catch (EMissingCredential | EInvalidCredentials e) { // authentication failure

            logger.warn("Unable to authenticate user with certificate " + auditSubjectID + ": " + e.getMessage());

            signedAuditLogger.log(AuthEvent.createFailureEvent(
                    auditSubjectID,
                    AuthSubsystem.CERTUSERDB_AUTHMGR_ID,
                    attemptedAuditUID));

            return null;

        } catch (Exception e) { // internal server error (e.g. LDAP exceptions)

            logger.warn("Unable to authenticate user with certificate " + auditSubjectID + ": " + e.getMessage(), e);

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
            return getPrincipal(username, (AuthToken) null);

        } catch (Exception e) {
            logger.warn("Unable to get principal for " + username + ": " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    protected Principal getPrincipal(String username, AuthToken authToken) throws Exception {
        User user = getUser(username);
        return getPrincipal(user, authToken);
    }

    protected Principal getPrincipal(User user, AuthToken authToken) throws EUsrGrpException {
        List<String> roles = getRoles(user);
        return new PKIPrincipal(user, null, roles, authToken);
    }

    protected User getUser(String username) throws EUsrGrpException {
        UGSubsystem ugSub = engine.getUGSubsystem();
        User user = ugSub.getUser(username);
        logger.info("PKIRealm: User DN: " + user.getUserDN());
        return user;
    }

    protected List<String> getRoles(User user) throws EUsrGrpException {

        List<String> roles = new ArrayList<>();

        UGSubsystem ugSub = engine.getUGSubsystem();
        Enumeration<Group> groups = ugSub.findGroupsByUser(user.getUserDN(), null);

        logger.info("PKIRealm: Roles:");
        while (groups.hasMoreElements()) {
            Group group = groups.nextElement();

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
