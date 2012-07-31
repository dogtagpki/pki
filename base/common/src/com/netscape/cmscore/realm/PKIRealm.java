package com.netscape.cmscore.realm;

import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.certsrv.usrgrp.IGroup;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.common.AuthCredentials;
import com.netscape.cmscore.authentication.CertUserDBAuthentication;
import com.netscape.cmscore.authentication.PasswdUserDBAuthentication;

/**
 *  PKI Realm
 *
 *  This realm provides an authentication service against PKI user database.
 *  The realm also provides an authorization service that validates request
 *  URL's against the access control list defined in the internal database.
 */

public class PKIRealm extends RealmBase {

    public final static String PROP_AUTH_FILE_PATH = "/WEB-INF/auth.properties";
    public final static int EXPRESSION_SIZE = 2;

    ThreadLocal<IAuthToken> authToken = new ThreadLocal<IAuthToken>();
    Properties authzProperties;

    public PKIRealm() {
        logDebug("Creating PKI realm");
    }

    @Override
    protected void initInternal() throws LifecycleException {
        logDebug("Initializing PKI realm");
        super.initInternal();
    }

    @Override
    protected void startInternal() throws LifecycleException {
        logDebug("Starting PKI realm");
        super.startInternal();
    }

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
            creds.set(PasswdUserDBAuthentication.CRED_UID, username);
            creds.set(PasswdUserDBAuthentication.CRED_PWD, password);

            IAuthToken token = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(token);

            return getPrincipal(username);

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
            creds.set(CertUserDBAuthentication.CRED_CERT, certImpls);

            IAuthToken token = authMgr.authenticate(creds); // throws exception if authentication fails
            authToken.set(token);

            String username = token.getInString(CertUserDBAuthentication.TOKEN_USERID);
            logDebug("User ID: "+username);

            return getPrincipal(username);

        } catch (Throwable e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    protected Principal getPrincipal(String username) {
        try {
            IUser user = getUser(username);
            return getPrincipal(user);

        } catch (Throwable e) {
            e.printStackTrace();
            return null;
        }
    }

    protected Principal getPrincipal(IUser user) throws EUsrGrpException {
        List<String> roles = getRoles(user);
        return new GenericPrincipal(user.getUserID(), null, roles);
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

    /**
     * Perform access control based on the specified authorization constraint.
     * Return <code>true</code> if this constraint is satisfied and processing
     * should continue, or <code>false</code> otherwise.
     * override to check for custom PKI ACL's authz permissions.
     *
     * @param request Request we are processing
     * @param response Response we are creating
     * @param constraints Security constraint we are enforcing
     * @param context The Context to which client of this class is attached.
     *
     * @exception IOException if an input/output error occurs
     */
    @Override
    public boolean hasResourcePermission(Request request,
            Response response,
            SecurityConstraint[] constraints,
            Context context)
            throws IOException {

        String requestURI = request.getDecodedRequestURI();
        logDebug("Checking permission: "+requestURI);

        boolean allowed = super.hasResourcePermission(request, response, constraints, context);
        logDebug("Resource permission: "+allowed);

        if (allowed) {
            allowed = checkACL(request, response, constraints, context);
            logDebug("ACL permission: "+allowed);
        }

        if (!allowed) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, sm.getString("realmBase.forbidden"));
        }

        return allowed;
    }

    public boolean checkACL(Request request,
            Response response,
            SecurityConstraint[] constraints,
            Context context) {

        try {
            loadAuthzProperties(context);
            if (!hasAuthzProperties()) return false;

            String requestURI = request.getDecodedRequestURI();
            String match = getACLEntry(requestURI);
            if (match == null) return false;

            logDebug("ACL: "+match);
            String[] authzParams = match.split("\\,");

            String resource = null;
            String operation = null;

            if (authzParams.length >= EXPRESSION_SIZE) {
                resource = authzParams[0];
                operation = authzParams[1];

                if (resource != null) {
                    resource = resource.trim();
                }

                if (operation != null) {
                    operation = operation.trim();
                }
            }

            IAuthzSubsystem mAuthz = (IAuthzSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTHZ);
            IAuthToken token = authToken.get();

            logDebug("Auth token:");
            Enumeration<String> names = token.getElements();
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                Object value = token.get(name);
                logDebug("  " + name +": " + value);
            }

            logDebug("Resource: " + resource);
            logDebug("Operation: " + operation);

            AuthzToken authzToken = mAuthz.authorize("DirAclAuthz", token, resource, operation);
            if (authzToken != null) return true;

        } catch (Throwable e) {
            e.printStackTrace();
        }

        return false;
    }

    // Search for the proper auth.properties entry corresponding
    // to a particular incoming URL
    // TODO: In the admin interface, often the operation is sent
    // as one of the parameters to the message.
    // There may be a way to extract this information at this level.
    // The parameter name to scan for could be configured with the Realm.

    public String getACLEntry(String requestURI) {

        if (!hasAuthzProperties()) {
            return null;
        }

        logDebug("Checking path: "+requestURI);
        String aclEntryData = authzProperties.getProperty(requestURI);

        if (aclEntryData != null) {
            logDebug("Found exact match: "+aclEntryData);
            return aclEntryData;
        }

        // Check for a partial match such as
        // ex: /kra/pki/keyrequest/2
        // TODO: Check into more sophisticated
        // methods of doing this mapping.
        // Perhaps Rest gives us this more
        // sophisticated mapping ability.

        Properties props = authzProperties;
        Enumeration<?> e = props.propertyNames();

        while (e.hasMoreElements()) {
            String key = (String) e.nextElement();
            if (requestURI.startsWith(key)) {
                aclEntryData = props.getProperty(key);
                logDebug("Found partial match ["+key+"]: "+aclEntryData);
                break;
            }
        }

        if (aclEntryData == null) {
            logDebug("No match found");
        }

        return aclEntryData;

    }

    // Check to see if we have read in the auth properties file
    public boolean hasAuthzProperties() {

        if (authzProperties != null) {
            return true;
        } else {
            return false;
        }
    }

    // Load the custom mapping file auth.properties, which maps urls to acl resourceID and operation value
    // example entry: /kra/pki/config/cert/transport = certServer.kra.pki.config.cert.transport,read
    // TODO: Look into a more sophisticated method than this simple properties file if appropriate.
    public synchronized void loadAuthzProperties(Context context) throws IOException {

        if (authzProperties == null && context != null) {

            InputStream inputStream = context.getServletContext().getResourceAsStream(PROP_AUTH_FILE_PATH);

            if (inputStream == null) {
                logDebug("Resource "+PROP_AUTH_FILE_PATH+" not found.");
                throw new IOException("Resource "+PROP_AUTH_FILE_PATH+" not found.");
            }

            try {
                logDebug("Loading authorization properties");

                Properties properties = new Properties();
                properties.load(inputStream);

                authzProperties = properties;

            } finally {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
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
