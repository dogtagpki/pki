package com.netscape.cms.realm;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import netscape.security.x509.X509CertImpl;

import org.apache.catalina.realm.RealmBase;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authentication.ICertUserDBAuthentication;
import com.netscape.certsrv.authentication.IPasswdUserDBAuthentication;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.common.AuthCredentials;

/**
 *  PKI Realm
 *
 *  This realm provides an authentication service against PKI user database.
 *  The realm also provides an authorization service that validates request
 *  URL's against the access control list defined in the internal database.
 */

public class PKIRealm extends RealmBase {

    @Override
    protected String getName() {
        return "PKIRealm";
    }

    @Override
    public Principal authenticate(String username, String password) {
        logDebug("Authenticating username "+username+" with password.");

        try {
            IAuthSubsystem authSub = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
            IAuthManager authMgr = authSub.getAuthManager(IAuthSubsystem.PASSWDUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(IPasswdUserDBAuthentication.CRED_UID, username);
            creds.set(IPasswdUserDBAuthentication.CRED_PWD, password);

            IAuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails

            return getPrincipal(username, authToken);

        } catch (Throwable e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    public Principal authenticate(final X509Certificate certs[]) {
        logDebug("Authenticating certificate chain:");

        try {
            X509CertImpl certImpls[] = new X509CertImpl[certs.length];
            for (int i=0; i<certs.length; i++) {
                X509Certificate cert = certs[i];
                logDebug("  "+cert.getSubjectDN());

                // Convert sun.security.x509.X509CertImpl to netscape.security.x509.X509CertImpl
                certImpls[i] = new X509CertImpl(cert.getEncoded());
            }

            IAuthSubsystem authSub = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
            IAuthManager authMgr = authSub.getAuthManager(IAuthSubsystem.CERTUSERDB_AUTHMGR_ID);

            AuthCredentials creds = new AuthCredentials();
            creds.set(ICertUserDBAuthentication.CRED_CERT, certImpls);

            IAuthToken authToken = authMgr.authenticate(creds); // throws exception if authentication fails

            String username = authToken.getInString(ICertUserDBAuthentication.TOKEN_USERID);
            logDebug("User ID: "+username);

            return getPrincipal(username, authToken);

        } catch (Throwable e) {
            e.printStackTrace();
        }

        return null;
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
        return new PKIPrincipal(user.getUserID(), null, roles, authToken);
    }

    protected IUser getUser(String username) throws EUsrGrpException {
        IUGSubsystem ugSub = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
        IUser user = ugSub.getUser(username);
        logDebug("User DN: "+user.getUserDN());
        return user;
    }

    protected List<String> getRoles(IUser user) throws EUsrGrpException {

        List<String> roles = new ArrayList<String>();

        IUGSubsystem ugSub = (IUGSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_UG);
        Enumeration<IGroup> groups = ugSub.findGroupsByUser(user.getUserDN());

        logDebug("Roles:");
        while (groups.hasMoreElements()) {
            IGroup group = groups.nextElement();

            String name = group.getName();
            logDebug("  "+name);
            roles.add(name);
        }

        return roles;
    }

    @Override
    protected String getPassword(String username) {
        return null;
    }

    /*
     * TODO: Figure out how to do real logging
     */
    public void logErr(String msg) {
        System.err.println(msg);
    }

    public void logDebug(String msg) {
        System.out.println("PKIRealm: "+msg);
    }
}
