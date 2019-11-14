package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.catalina.realm.RealmBase;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.server.authentication.IAuthManager;
import org.dogtagpki.server.authentication.IAuthSubsystem;
import org.dogtagpki.server.authentication.ICertUserDBAuthentication;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

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
        logger.info("Authenticating user " + username + " with password.");

        CMSEngine engine = CMS.getCMSEngine();
        String auditSubjectID = ILogger.UNIDENTIFIED;
        String attemptedAuditUID = username;

        try {
            IAuthSubsystem authSub = (IAuthSubsystem) engine.getSubsystem(IAuthSubsystem.ID);
            IAuthManager authMgr = authSub.getAuthManager(IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(IPasswdUserDBAuthentication.CRED_UID, username);
            creds.set(IPasswdUserDBAuthentication.CRED_PWD, password);

            IAuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(SessionContext.AUTH_MANAGER_ID, IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);
            auditSubjectID = authToken.getInString(IAuthToken.USER_ID);

            signedAuditLogger.log(AuthEvent.createSuccessEvent(
                        auditSubjectID,
                        IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID));

            return getPrincipal(username, authToken);

        } catch (Throwable e) {

            signedAuditLogger.log(AuthEvent.createFailureEvent(
                        auditSubjectID,
                        IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID,
                        attemptedAuditUID));

            e.printStackTrace();
        }

        return null;
    }

    @Override
    public Principal authenticate(final X509Certificate[] certs) {
        logger.info("Authenticating certificate chain:");

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
                logger.info("- " + cert.getSubjectDN());

                // Convert sun.security.x509.X509CertImpl to org.mozilla.jss.netscape.security.x509.X509CertImpl
                certImpls[i] = new X509CertImpl(cert.getEncoded());
            }
            IAuthSubsystem authSub = (IAuthSubsystem) engine.getSubsystem(IAuthSubsystem.ID);
            IAuthManager authMgr = authSub.getAuthManager(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(ICertUserDBAuthentication.CRED_CERT, certImpls);

            IAuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(SessionContext.AUTH_MANAGER_ID,IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            String username = authToken.getInString(ICertUserDBAuthentication.TOKEN_USERID);
            // reset it to the one authenticated with authManager
            auditSubjectID = authToken.getInString(IAuthToken.USER_ID);

            logger.info("User ID: " + username);

            signedAuditLogger.log(AuthEvent.createSuccessEvent(
                        auditSubjectID,
                        IAuthSubsystem.CERTUSERDB_AUTHMGR_ID));

            return getPrincipal(username, authToken);

        } catch (Throwable e) {

            signedAuditLogger.log(AuthEvent.createFailureEvent(
                        auditSubjectID,
                        IAuthSubsystem.CERTUSERDB_AUTHMGR_ID,
                        attemptedAuditUID));

            e.printStackTrace();
        }

        return null;
    }

    private String getAuditUserfromCert(X509Certificate clientCert) {
        String certUID = clientCert.getSubjectDN().getName();
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
        CMSEngine engine = CMS.getCMSEngine();
        UGSubsystem ugSub = (UGSubsystem) engine.getSubsystem(UGSubsystem.ID);
        IUser user = ugSub.getUser(username);
        logger.info("User DN: " + user.getUserDN());
        return user;
    }

    protected List<String> getRoles(IUser user) throws EUsrGrpException {

        List<String> roles = new ArrayList<String>();

        CMSEngine engine = CMS.getCMSEngine();
        UGSubsystem ugSub = (UGSubsystem) engine.getSubsystem(UGSubsystem.ID);
        Enumeration<IGroup> groups = ugSub.findGroupsByUser(user.getUserDN(), null);

        logger.info("Roles:");
        while (groups.hasMoreElements()) {
            IGroup group = groups.nextElement();

            String name = group.getName();
            logger.info("- " + name);
            roles.add(name);
        }

        return roles;
    }

    @Override
    protected String getPassword(String username) {
        return null;
    }
}
