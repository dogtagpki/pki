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
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.realm;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthToken;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.AuthEvent;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authentication.AuthSubsystem;
import com.netscape.cmscore.authentication.PasswdUserDBAuthentication;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

/**
 * Container-agnostic PKI authentication logic.
 *
 * This class extracts the authentication and role lookup logic from
 * PKIRealm (which extends Tomcat's RealmBase) so it can be reused
 * by both Tomcat and Quarkus security mechanisms.
 *
 * NOTE: This class will be moved to pki-server-core once its
 * dependencies (CMSEngine, AuthSubsystem, etc.) are moved there.
 */
public class PKIAuthenticator {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PKIAuthenticator.class);

    private final CMSEngine engine;

    public PKIAuthenticator(CMSEngine engine) {
        this.engine = engine;
    }

    /**
     * Authenticate a user by username and password.
     *
     * @return a PKIPrincipalCore on success, or null on authentication failure
     * @throws RuntimeException on internal errors (e.g. LDAP issues)
     */
    public PKIPrincipalCore authenticateByPassword(String username, String password) {

        logger.info("PKIAuthenticator: Authenticating user " + username + " with password");

        Auditor auditor = engine.getAuditor();
        String auditSubjectID = ILogger.UNIDENTIFIED;
        String attemptedAuditUID = username;

        try {
            AuthSubsystem authSub = engine.getAuthSubsystem();
            AuthManager authMgr = authSub.getAuthManager(AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(PasswdUserDBAuthentication.CRED_UID, username);
            creds.set(PasswdUserDBAuthentication.CRED_PWD, password);

            AuthToken authToken = authMgr.authenticate(creds);
            authToken.set(SessionContext.AUTH_MANAGER_ID, AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);
            auditSubjectID = authToken.getInString(AuthToken.USER_ID);

            logger.info("PKIAuthenticator: User " + username + " authenticated");

            auditor.log(AuthEvent.createSuccessEvent(
                    auditSubjectID,
                    AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID));

            return createPrincipal(username, authToken);

        } catch (EMissingCredential | EInvalidCredentials e) {

            logger.warn("Unable to authenticate user " + username + ": " + e.getMessage());

            auditor.log(AuthEvent.createFailureEvent(
                    auditSubjectID,
                    AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID,
                    attemptedAuditUID));

            return null;

        } catch (Exception e) {

            logger.warn("Unable to authenticate user " + username + ": " + e.getMessage(), e);

            auditor.log(AuthEvent.createFailureEvent(
                    auditSubjectID,
                    AuthSubsystem.PASSWDUSERDB_AUTHMGR_ID,
                    attemptedAuditUID));

            throw new RuntimeException(e);
        }
    }

    /**
     * Authenticate a user by X.509 certificate chain.
     *
     * @return a PKIPrincipalCore on success, or null on authentication failure
     * @throws RuntimeException on internal errors
     */
    public PKIPrincipalCore authenticateByCertificate(X509Certificate[] certs) {

        logger.info("PKIAuthenticator: Authenticating certificate chain:");
        for (X509Certificate cert : certs) {
            logger.info("PKIAuthenticator: - Serial Number: " + new CertId(cert.getSerialNumber()).toHexString());
            logger.info("PKIAuthenticator:   Subject DN: " + cert.getSubjectX500Principal());
        }

        Auditor auditor = engine.getAuditor();
        String auditSubjectID = getAuditUserFromCert(certs[0]);
        String attemptedAuditUID = auditSubjectID;

        try {
            X509CertImpl[] certImpls = new X509CertImpl[certs.length];
            for (int i = 0; i < certs.length; i++) {
                certImpls[i] = new X509CertImpl(certs[i].getEncoded());
            }

            AuthSubsystem authSub = engine.getAuthSubsystem();
            AuthManager authMgr = authSub.getAuthManager(AuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(AuthManager.CRED_SSL_CLIENT_CERT, certImpls);

            AuthToken authToken = authMgr.authenticate(creds);
            authToken.set(SessionContext.AUTH_MANAGER_ID, AuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            String username = authToken.getInString(AuthToken.USER_ID);
            auditSubjectID = username;

            logger.info("PKIAuthenticator: User " + username + " authenticated");

            auditor.log(AuthEvent.createSuccessEvent(
                    auditSubjectID,
                    AuthSubsystem.CERTUSERDB_AUTHMGR_ID));

            return createPrincipal(username, authToken);

        } catch (EMissingCredential | EInvalidCredentials e) {

            logger.warn("Unable to authenticate user with certificate " + auditSubjectID + ": " + e.getMessage());

            auditor.log(AuthEvent.createFailureEvent(
                    auditSubjectID,
                    AuthSubsystem.CERTUSERDB_AUTHMGR_ID,
                    attemptedAuditUID));

            return null;

        } catch (Exception e) {

            logger.warn("Unable to authenticate user with certificate " + auditSubjectID + ": " + e.getMessage(), e);

            auditor.log(AuthEvent.createFailureEvent(
                    auditSubjectID,
                    AuthSubsystem.CERTUSERDB_AUTHMGR_ID,
                    attemptedAuditUID));

            throw new RuntimeException(e);
        }
    }

    /**
     * Create a PKIPrincipalCore for the given username.
     */
    public PKIPrincipalCore createPrincipal(String username, AuthToken authToken) throws Exception {
        User user = getUser(username);
        List<String> roles = getRoles(user);
        return new PKIPrincipalCore(user.getUserID(), null, roles, user, authToken);
    }

    /**
     * Look up a user from the internal user/group database.
     */
    public User getUser(String username) throws EUsrGrpException {
        UGSubsystem ugSub = engine.getUGSubsystem();
        User user = ugSub.getUser(username);
        logger.info("PKIAuthenticator: User DN: " + user.getUserDN());
        return user;
    }

    /**
     * Get the roles (groups) for a user.
     */
    public List<String> getRoles(User user) throws EUsrGrpException {

        List<String> roles = new ArrayList<>();

        UGSubsystem ugSub = engine.getUGSubsystem();
        Enumeration<Group> groups = ugSub.findGroupsByUser(user.getUserDN(), null);

        logger.info("PKIAuthenticator: Roles:");
        while (groups.hasMoreElements()) {
            Group group = groups.nextElement();
            String name = group.getName();
            logger.info("PKIAuthenticator: - " + name);
            roles.add(name);
        }

        return roles;
    }

    private String getAuditUserFromCert(X509Certificate clientCert) {
        String certUID = clientCert.getSubjectDN().getName();
        return StringUtils.stripToNull(certUID);
    }
}
