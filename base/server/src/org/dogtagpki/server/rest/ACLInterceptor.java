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

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.authorization.AuthzToken;
import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.spi.Failure;

import com.netscape.certsrv.acls.ACLMapping;
import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogEvent;
import com.netscape.certsrv.logging.event.AuthzEvent;
import com.netscape.cms.logging.Logger;
import com.netscape.cms.logging.SignedAuditLogger;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authorization.AuthzSubsystem;

/**
 * @author Endi S. Dewata
 */
@Provider
public class ACLInterceptor implements ContainerRequestFilter {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACLInterceptor.class);
    private static Logger signedAuditLogger = SignedAuditLogger.getLogger();

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
        logger.debug("ACLInterceptor: loading " + defaultMapping);
        try (FileReader in = new FileReader(defaultMapping)) {
            properties.load(in);
        }

        // load custom mapping
        File customMapping = new File(System.getProperty("catalina.base")
                + "/" + subsystem + "/conf/acl.properties");
        logger.debug("ACLInterceptor: checking " + customMapping);
        if (customMapping.exists()) {
            logger.debug("ACLInterceptor: loading " + customMapping);
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

        logger.debug("ACLInterceptor: " + auditInfo + "()");
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
            logger.debug("ACLInterceptor.filter: no authorization required");
            authzRequired = false;
        }

        Principal principal = null;
        principal = securityContext.getUserPrincipal();

        // If unauthenticated, reject request.
        if (principal == null && authzRequired) {
            logger.debug("ACLInterceptor: No user principal provided.");
            // audit comment: no Principal, no one to blame here
            throw new ForbiddenException("No user principal provided.");
        }
        if (principal != null)
            logger.debug("ACLInterceptor: principal: " + principal.getName());

        CMSEngine engine = CMS.getCMSEngine();
        AuthzSubsystem authzSubsystem = engine.getAuthzSubsystem();

        IAuthToken authToken = null;
        String authzMgrName = null;
        if (principal != null) {
            if (principal instanceof PKIPrincipal) {
                authzMgrName = "DirAclAuthz";
                authToken = ((PKIPrincipal) principal).getAuthToken();
            }
            else if (principal instanceof GenericPrincipal) {
                String realm = null;
                String[] parts = principal.getName().split("@", 2);
                if (parts.length == 2) {
                    realm = parts[1];
                }
                try {
                    authzMgrName = authzSubsystem.getAuthzManagerNameByRealm(realm);
                } catch (EAuthzUnknownRealm e) {
                    throw new ForbiddenException(
                        "Cannot find AuthzManager for external principal " + principal.getName(),
                        e
                    );
                }
                authToken = new ExternalAuthToken((GenericPrincipal) principal);
            }
            logger.debug("ACLInterceptor: will use authz manager " + authzMgrName);
        }

        // If missing auth token, reject request.
        if (authToken == null && authzRequired) {
            logger.debug("ACLInterceptor: No authentication token present.");
            // store a message in the signed audit log file
            // although if it didn't pass authentication, it should not have gotten here
            audit(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        null, // resource
                        null, // operation
                        LOGGING_MISSING_AUTH_TOKEN + ":" + auditInfo));

            throw new ForbiddenException("No authorization token present.");
        }
        if (authToken != null)
            auditSubjectID = authToken.getInString(IAuthToken.USER_ID);

        // If still not available, it's unprotected, allow request.
        if (!authzRequired) {
            logger.debug("ACLInterceptor: No ACL mapping; authz not required.");

            audit(AuthzEvent.createSuccessEvent(
                        auditSubjectID,
                        null, //resource
                        null, //operation
                        LOGGING_MISSING_ACL_MAPPING + ":" + auditInfo)); //info

            return;
        }

        // we know aclMapping is not null now (!noAuthzRequired); authz game on...
        String name = aclMapping.value();
        logger.debug("ACLInterceptor: mapping: " + name);

        String values[] = null;
        String value = null;
        try {
            loadProperties();

            value = properties.getProperty(name);

        } catch (IOException e) {

            audit(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        null, //resource
                        null, //operation
                        LOGGING_ACL_PARSING_ERROR + ":" + auditInfo));

            e.printStackTrace();
            throw new Failure(e);
        }

        // If no property defined, allow request.
        if (value == null) {
            logger.debug("ACLInterceptor: No ACL configuration.");

            audit(AuthzEvent.createSuccessEvent(
                    auditSubjectID,
                    null, //resource
                    null, //operation
                    LOGGING_NO_ACL_ACCESS_ALLOWED + ":" + auditInfo));

            return;
        }

        values = value.split(",");

        // If invalid mapping, reject request.
        if (values.length != 2) {
            logger.error("ACLInterceptor: Invalid ACL mapping: " + value);

            audit(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    null, //resource
                    null, //operation
                    LOGGING_INVALID_ACL_MAPPING + ":" + auditInfo));

            throw new ForbiddenException("Invalid ACL mapping.");
        }

        logger.debug("ACLInterceptor: ACL: " + value);

        try {
            // Check authorization.
            AuthzToken authzToken = authzSubsystem.authorize(
                    authzMgrName,
                    authToken,
                    values[0], // resource
                    values[1]); // operation

            // If not authorized, reject request.
            if (authzToken == null) {
                String info = "No authorization token present.";
                logger.debug("ACLInterceptor: " + info);

                audit(AuthzEvent.createFailureEvent(
                            auditSubjectID,
                            values[0], // resource
                            values[1], // operation
                            info));

                throw new ForbiddenException("No authorization token present.");
            }

            logger.debug("ACLInterceptor: access granted");

        } catch (EAuthzAccessDenied e) {
            String info = e.getMessage();
            logger.debug("ACLInterceptor: " + info);

            audit(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        values[0], // resource
                        values[1], // operation
                        info));

            throw new ForbiddenException(e.toString());

        } catch (EBaseException e) {
            String info = e.getMessage();
            logger.error("ACLInterceptor: " + info, e);

            audit(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        values[0], // resource
                        values[1], // operation
                        info));

            throw new Failure(e);
        }

        // Allow request.

        audit(AuthzEvent.createSuccessEvent(
                    auditSubjectID,
                    values[0], // resource
                    values[1], // operation
                    auditInfo));

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
        signedAuditLogger.log(msg);
    }

    protected void audit(LogEvent event) {
        signedAuditLogger.log(event);
    }
}
