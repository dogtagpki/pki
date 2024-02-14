//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.v2;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.util.Properties;

import javax.servlet.FilterChain;
import javax.servlet.GenericFilter;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;
import org.jboss.resteasy.spi.Failure;

import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.AuthzEvent;
import com.netscape.certsrv.logging.event.RoleAssumeEvent;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.logging.Auditor;

/**
 *
 */
/**
 *
 */
public abstract class ACLFilter extends GenericFilter {

    private static final long serialVersionUID = 1L;
    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACLFilter.class);
    private static final String LOGGING_ACL_PARSING_ERROR = "internal error: ACL parsing error";
    private static final String LOGGING_NO_ACL_ACCESS_ALLOWED = "no ACL configured; OK";
    private static final String LOGGING_MISSING_AUTH_TOKEN = "auth token not found";
    private static final String LOGGING_MISSING_ACL_MAPPING = "ACL mapping not found; OK";
    private static final String LOGGING_INVALID_ACL_MAPPING = "internal error: invalid ACL mapping";
    private Properties aclProperties;
    private String acl;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        if(request instanceof HttpServletRequest req &&
                response instanceof HttpServletResponse resp) {
            try {
                checkACL(req, acl);
            } catch (ForbiddenException fe) {
                resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
        chain.doFilter(request, response);
    }

    private CMSEngine getCMSEngine() {
        ServletContext servletContext = getServletContext();
        return (CMSEngine) servletContext.getAttribute("engine");
    }

    private synchronized void loadACLProperties() throws IOException {

        if (aclProperties != null)
            return;

        aclProperties = new Properties();

        String context = getServletContext().getContextPath();
        String subsystem = context.startsWith("/") ? context.substring(1) : context;

        // load default mapping
        Path defaultMappingACL = Paths.get("/usr/share/pki", subsystem, "conf", "acl.properties");
        File defaultMapping = defaultMappingACL.toFile();
        logger.debug("AgentCertRequestACLFilter: loading {}", defaultMappingACL);
        try (FileReader in = new FileReader(defaultMapping)) {
            aclProperties.load(in);
        }

        // load custom mapping
        Path customMappingACL = Paths.get(CMS.getInstanceDir(), subsystem, "conf", "acl.properties");
        File customMapping = customMappingACL.toFile();
        logger.debug("AgentCertRequestACLFilter: checking {}", customMapping);
        if (customMapping.exists()) {
            logger.debug("AgentCertRequestACLFilter: loading {}",   customMappingACL);
            try (FileReader in = new FileReader(customMapping)) {
                aclProperties.load(in);
            }
        }
    }

    protected void checkACL(HttpServletRequest request, String name) throws ForbiddenException {
        String auditInfo =  request.getMethod() + ":" + request.getPathInfo();

        logger.debug("ACLFilter: {}", auditInfo);
        String auditSubjectID = ILogger.UNIDENTIFIED;

        /*
         * when aclMapping is null, it's either of the following :
         *   - only authentication needed
         *   - allows anonymous, i.e. no authentication or authorization needed
         * use authzRequired to track when aclMapping is not null for ease of following the code
         */
        boolean authzRequired = true;
        if (name == null || name.isEmpty()) {
            logger.debug("ACLFilter: no authorization required");
            authzRequired = false;
        }

        Principal principal = request.getUserPrincipal();

        // If unauthenticated, reject request.
        if (principal == null && authzRequired) {
            logger.debug("ACLFilter: No user principal provided.");
            // audit comment: no Principal, no one to blame here
            throw new ForbiddenException("No user principal provided.");
        }
        if (principal != null)
            logger.debug("ACLFilter: principal: {}", principal.getName());

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();
        AuthzSubsystem authzSubsystem = engine.getAuthzSubsystem();

        AuthToken authToken = null;
        String authzMgrName = null;
        if (principal != null) {
            if (principal instanceof PKIPrincipal pkiPrincipal) {
                authzMgrName = "DirAclAuthz";
                authToken = pkiPrincipal.getAuthToken();
            }
            else {
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
            logger.debug("ACLFilter: will use authz manager {}", authzMgrName);
        }

        // If missing auth token, reject request.
        if (authToken == null && authzRequired) {
            logger.debug("ACLFilter: No authentication token present.");
            // store a message in the signed audit log file
            // although if it didn't pass authentication, it should not have gotten here
            auditor.log(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        null, // resource
                        null, // operation
                        LOGGING_MISSING_AUTH_TOKEN + ":" + auditInfo));

            throw new ForbiddenException("No authorization token present.");
        }
        if (authToken != null)
            auditSubjectID = authToken.getInString(AuthToken.USER_ID);

        // If still not available, it's unprotected, allow request.
        if (!authzRequired) {
            logger.debug("ACLFilter: Unprotected resource; access granted");

            auditor.log(AuthzEvent.createSuccessEvent(
                        auditSubjectID,
                        null, //resource
                        null, //operation
                        LOGGING_MISSING_ACL_MAPPING + ":" + auditInfo)); //info

            // unprotected resource -> do not generate ROLE_ASSUME event

            return;
        }

        // we know aclMapping is not null now (!noAuthzRequired); authz game on...
        logger.debug("ACLFilter: mapping: {}", name);

        String[] values = null;
        String value = null;
        try {
            loadACLProperties();

            value = aclProperties.getProperty(name);

        } catch (IOException e) {

            auditor.log(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        null, //resource
                        null, //operation
                        LOGGING_ACL_PARSING_ERROR + ":" + auditInfo));

            e.printStackTrace();
            throw new Failure(e);
        }

        // If no property defined, allow request.
        if (value == null) {
            logger.debug("ACLFilter: Unprotected resource; access granted");

            auditor.log(AuthzEvent.createSuccessEvent(
                    auditSubjectID,
                    null, //resource
                    null, //operation
                    LOGGING_NO_ACL_ACCESS_ALLOWED + ":" + auditInfo));

            // unprotected resource -> do not generate ROLE_ASSUME event

            return;
        }

        // accessing protected resource

        values = value.split(",");

        // If invalid mapping, reject request.
        if (values.length != 2) {
            logger.error("ACLFilter: Invalid ACL mapping: {}", value);

            auditor.log(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    null, //resource
                    null, //operation
                    LOGGING_INVALID_ACL_MAPPING + ":" + auditInfo));

            throw new ForbiddenException("Invalid ACL mapping.");
        }

        logger.debug("ACLFilter: ACL: {}", value);

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
                logger.debug("ACLFilter: {}", info);

                auditor.log(AuthzEvent.createFailureEvent(
                            auditSubjectID,
                            values[0], // resource
                            values[1], // operation
                            info));

                throw new ForbiddenException("No authorization token present.");
            }

            logger.debug("ACLFilter: access granted");

        } catch (EAuthzAccessDenied e) {
            String info = e.getMessage();
            logger.debug("ACLFilter: {}", info);

            auditor.log(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        values[0], // resource
                        values[1], // operation
                        info));

            throw new ForbiddenException(e.toString());

        } catch (EBaseException e) {
            String info = e.getMessage();
            logger.error("ACLFilter: " + info, e);

            auditor.log(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        values[0], // resource
                        values[1], // operation
                        info));

            throw new Failure(e);
        }

        logger.debug("ACLFilter: Protected resource; access granted");

        auditor.log(AuthzEvent.createSuccessEvent(
                    auditSubjectID,
                    values[0], // resource
                    values[1], // operation
                    auditInfo));

        if (principal instanceof PKIPrincipal pkiPrincipal) {
            String[] roles = pkiPrincipal.getRoles();
            if (roles != null) {
                auditor.log(RoleAssumeEvent.createSuccessEvent(
                        auditSubjectID,
                        String.join(",", roles)));
            }
        }

    }

    public void setAcl(String acl) {
        this.acl = acl;
    }

}