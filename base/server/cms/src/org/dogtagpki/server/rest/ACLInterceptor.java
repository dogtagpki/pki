//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.rest;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;

import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.spi.Failure;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.realm.PKIPrincipal;

/**
 * @author Endi S. Dewata
 */
@Provider
public class ACLInterceptor implements ContainerRequestFilter {
    protected ILogger signedAuditLogger = CMS.getSignedAuditLogger();
    private final static String LOGGING_SIGNED_AUDIT_AUTHZ_FAIL =
            "LOGGING_SIGNED_AUDIT_AUTHZ_FAIL_5";
    private final static String LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS =
            "LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS_5";

    private final static String LOGGING_ACL_PARSING_ERROR = "internal error: ACL parsing error";
    private final static String LOGGING_NO_ACL_ACCESS_ALLOWED = "no ACL configured; OK";
    private final static String LOGGING_MISSING_AUTH_TOKEN = "auth token not found";
    private final static String LOGGING_MISSING_ACL_MAPPING = "ACL mapping not found; OK";
    private final static String LOGGING_INVALID_ACL_MAPPING = "internal error: invalid ACL mapping";

    Properties properties;

    @Context
    ServletContext servletContext;

    @Context
    SecurityContext securityContext;

    public synchronized void loadProperties() throws IOException {

        if (properties != null)
            return;

        properties = new Properties();

        String context = servletContext.getContextPath();
        String subsystem = context.startsWith("/") ? context.substring(1) : context;

        // load default mapping
        String defaultMapping = "/usr/share/pki/" + subsystem + "/conf/acl.properties";
        CMS.debug("ACLInterceptor: loading " + defaultMapping);
        try (FileReader in = new FileReader(defaultMapping)) {
            properties.load(in);
        }

        // load custom mapping
        File customMapping = new File(System.getProperty("catalina.base")
                + "/" + subsystem + "/conf/acl.properties");
        CMS.debug("ACLInterceptor: checking " + customMapping);
        if (customMapping.exists()) {
            CMS.debug("ACLInterceptor: loading " + customMapping);
            try (FileReader in = new FileReader(customMapping)) {
                properties.load(in);
            }
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        ResourceMethodInvoker methodInvoker = (ResourceMethodInvoker) requestContext
                .getProperty("org.jboss.resteasy.core.ResourceMethodInvoker");
        Method method = methodInvoker.getMethod();
        Class<?> clazz = methodInvoker.getResourceClass();
        String auditInfo =  clazz.getSimpleName() + "." + method.getName();

        CMS.debug("ACLInterceptor: " + auditInfo + "()");
        String auditMessage = null;
        String auditSubjectID = ILogger.UNIDENTIFIED;

        /*
         * when aclMapping is null, it's either of the following :
         *   - only authentication needed
         *   - allows anonymous, i.e. no authentication or authorization needed
         * use authzRequired to track when aclMapping is not null for ease of following the code
         */
        boolean authzRequired = true;
        ACLMapping aclMapping = method.getAnnotation(ACLMapping.class);
        // If not available, get ACL mapping for the class.
        if (aclMapping == null) {
            aclMapping = clazz.getAnnotation(ACLMapping.class);
        }
        if (aclMapping == null) {
            CMS.debug("ACLInterceptor.filter: no authorization required");
            authzRequired = false;
        }

        Principal principal = null;
        principal = securityContext.getUserPrincipal();

        // If unauthenticated, reject request.
        if (principal == null && authzRequired) {
            CMS.debug("ACLInterceptor: No user principal provided.");
            // audit comment: no Principal, no one to blame here
            throw new ForbiddenException("No user principal provided.");
        }
        if (principal != null)
            CMS.debug("ACLInterceptor: principal: " + principal.getName());

        // If unrecognized principal, reject request.
        if (principal != null && !(principal instanceof PKIPrincipal)) {
            CMS.debug("ACLInterceptor: Invalid user principal.");
            // audit comment: no Principal, no one to blame here
            throw new ForbiddenException("Invalid user principal.");
        }

        PKIPrincipal pkiPrincipal = null;
        IAuthToken authToken = null;
        if (principal != null) {
            pkiPrincipal = (PKIPrincipal) principal;
            authToken = pkiPrincipal.getAuthToken();
        }

        // If missing auth token, reject request.
        if (authToken == null && authzRequired) {
            CMS.debug("ACLInterceptor: No authentication token present.");
            // store a message in the signed audit log file
            // although if it didn't pass authentication, it should not have gotten here
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        null, // resource
                        null, // operation
                        LOGGING_MISSING_AUTH_TOKEN + ":" + auditInfo);
            audit(auditMessage);
            throw new ForbiddenException("No authorization token present.");
        }
        if (authToken != null)
            auditSubjectID = authToken.getInString(IAuthToken.USER_ID);

        // If still not available, it's unprotected, allow request.
        if (!authzRequired) {
            CMS.debug("ACLInterceptor: No ACL mapping; authz not required.");
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        null, //resource
                        null, //operation
                        LOGGING_MISSING_ACL_MAPPING + ":" + auditInfo); //info
            audit(auditMessage);
            return;
        }

        // we know aclMapping is not null now (!noAuthzRequired); authz game on...
        String name = aclMapping.value();
        CMS.debug("ACLInterceptor: mapping: " + name);

        String values[] = null;
        String value = null;
        try {
            loadProperties();

            value = properties.getProperty(name);

        } catch (IOException e) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        null, //resource
                        null, //operation
                        LOGGING_ACL_PARSING_ERROR + ":" + auditInfo);

            audit(auditMessage);
            e.printStackTrace();
            throw new Failure(e);
        }

        // If no property defined, allow request.
        if (value == null) {
            CMS.debug("ACLInterceptor: No ACL configuration.");
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    null, //resource
                    null, //operation
                    LOGGING_NO_ACL_ACCESS_ALLOWED + ":" + auditInfo);
            return;
        }

        values = value.split(",");

        // If invalid mapping, reject request.
        if (values.length != 2) {
            CMS.debug("ACLInterceptor: Invalid ACL mapping.");
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                    auditSubjectID,
                    ILogger.FAILURE,
                    null, //resource
                    null, //operation
                    LOGGING_INVALID_ACL_MAPPING + ":" + auditInfo);

            audit(auditMessage);
            throw new ForbiddenException("Invalid ACL mapping.");
        }

        CMS.debug("ACLInterceptor: ACL: " + value);

        try {
            // Check authorization.
            IAuthzSubsystem mAuthz = (IAuthzSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTHZ);
            AuthzToken authzToken = mAuthz.authorize(
                    "DirAclAuthz",
                    authToken,
                    values[0], // resource
                    values[1]); // operation

            // If not authorized, reject request.
            if (authzToken == null) {
                String info = "No authorization token present.";
                CMS.debug("ACLInterceptor: " + info);
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                            auditSubjectID,
                            ILogger.FAILURE,
                            values[0], // resource
                            values[1], // operation
                            info);
                audit(auditMessage);
                throw new ForbiddenException("No authorization token present.");
            }

            CMS.debug("ACLInterceptor: access granted");

        } catch (EAuthzAccessDenied e) {
            String info = e.getMessage();
            CMS.debug("ACLInterceptor: " + info);
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        values[0], // resource
                        values[1], // operation
                        info);
            audit(auditMessage);
            throw new ForbiddenException(e.toString());

        } catch (EBaseException e) {
            String info = e.getMessage();
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_AUTHZ_FAIL,
                        auditSubjectID,
                        ILogger.FAILURE,
                        values[0], // resource
                        values[1], // operation
                        info);
            audit(auditMessage);
            e.printStackTrace();
            throw new Failure(e);
        }

        // Allow request.
        // store a message in the signed audit log file
        auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_AUTHZ_SUCCESS,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    values[0], // resource
                    values[1], // operation
                    auditInfo);
        audit(auditMessage);
        return;
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
