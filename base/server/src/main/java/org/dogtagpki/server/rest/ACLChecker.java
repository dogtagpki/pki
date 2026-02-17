//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.util.Properties;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;

import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.AuthzEvent;
import com.netscape.certsrv.logging.event.RoleAssumeEvent;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.logging.Auditor;

/**
 * Container-agnostic ACL checking logic.
 *
 * Extracts the business logic from ACLFilter (which extends HttpFilter)
 * so it can be reused by both Tomcat servlet filters and Quarkus
 * ContainerRequestFilters.
 *
 * NOTE: This class will be moved to pki-server-core once its
 * dependencies (CMSEngine, AuthzSubsystem, etc.) are moved there.
 */
public class ACLChecker {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ACLChecker.class);

    private static final String LOGGING_ACL_PARSING_ERROR = "internal error: ACL parsing error";
    private static final String LOGGING_NO_ACL_ACCESS_ALLOWED = "no ACL configured; OK";
    private static final String LOGGING_MISSING_AUTH_TOKEN = "auth token not found";
    private static final String LOGGING_MISSING_ACL_MAPPING = "ACL mapping not found; OK";
    private static final String LOGGING_INVALID_ACL_MAPPING = "internal error: invalid ACL mapping";

    private final CMSEngine engine;
    private final String subsystem;
    private Properties aclProperties;

    public ACLChecker(CMSEngine engine, String subsystem) {
        this.engine = engine;
        this.subsystem = subsystem;
    }

    /**
     * Load ACL properties from the default and instance-specific files.
     */
    public synchronized void loadACLProperties() throws IOException {

        if (aclProperties != null)
            return;

        aclProperties = new Properties();

        // load default mapping
        Path defaultMappingACL = Paths.get("/usr/share/pki", subsystem, "conf", "acl.properties");
        File defaultMapping = defaultMappingACL.toFile();
        logger.debug("ACLChecker: loading {}", defaultMappingACL);
        try (FileReader in = new FileReader(defaultMapping)) {
            aclProperties.load(in);
        }

        // load custom mapping
        Path customMappingACL = Paths.get(CMS.getInstanceDir(), subsystem, "conf", "acl.properties");
        File customMapping = customMappingACL.toFile();
        logger.debug("ACLChecker: checking {}", customMapping);
        if (customMapping.exists()) {
            logger.debug("ACLChecker: loading {}", customMappingACL);
            try (FileReader in = new FileReader(customMapping)) {
                aclProperties.load(in);
            }
        }
    }

    /**
     * Check ACL authorization for the given principal and request.
     *
     * @param principal the authenticated principal (may be null)
     * @param httpMethod the HTTP method (GET, POST, etc.)
     * @param pathInfo the request path info
     * @param aclName the ACL mapping name to check
     * @param authTokenExtractor function to extract AuthToken from external principals
     * @throws ForbiddenException if authorization is denied
     */
    public void checkACL(Principal principal, String httpMethod, String pathInfo, String aclName)
            throws ForbiddenException {

        String auditInfo = httpMethod + ":" + (pathInfo != null ? pathInfo : "");

        logger.debug("ACLChecker: {}", auditInfo);
        String auditSubjectID = ILogger.UNIDENTIFIED;

        boolean authzRequired = true;
        String name = aclName;
        if (name == null || name.isEmpty()) {
            logger.debug("ACLChecker: no authorization required");
            authzRequired = false;
            name = "";
        }

        // If unauthenticated, reject request.
        if (principal == null && authzRequired) {
            logger.debug("ACLChecker: No user principal provided.");
            throw new ForbiddenException("No user principal provided.");
        }
        if (principal != null)
            logger.debug("ACLChecker: principal: {}", principal.getName());

        Auditor auditor = engine.getAuditor();
        AuthzSubsystem authzSubsystem = engine.getAuthzSubsystem();

        AuthToken authToken = null;
        String authzMgrName = null;
        if (principal != null) {
            if (principal instanceof PKIPrincipal pkiPrincipal) {
                authzMgrName = "DirAclAuthz";
                authToken = pkiPrincipal.getAuthToken();
            } else if (principal instanceof PKIPrincipalCore corePrincipal) {
                authzMgrName = "DirAclAuthz";
                authToken = (AuthToken) corePrincipal.getAuthToken();
            } else {
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
                            e);
                }
                authToken = extractExternalAuthToken(principal);
            }
            logger.debug("ACLChecker: will use authz manager {}", authzMgrName);
        }

        // If missing auth token, reject request.
        if (authToken == null && authzRequired) {
            logger.debug("ACLChecker: No authentication token present.");
            auditor.log(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    null,
                    null,
                    LOGGING_MISSING_AUTH_TOKEN + ":" + auditInfo));

            throw new ForbiddenException("No authorization token present.");
        }
        if (authToken != null)
            auditSubjectID = authToken.getInString(AuthToken.USER_ID);

        // If still not available, it's unprotected, allow request.
        if (!authzRequired) {
            logger.debug("ACLChecker: Unprotected resource; access granted");

            auditor.log(AuthzEvent.createSuccessEvent(
                    auditSubjectID,
                    null,
                    null,
                    LOGGING_MISSING_ACL_MAPPING + ":" + auditInfo));

            return;
        }

        // we know aclMapping is not null now; authz game on...
        logger.debug("ACLChecker: mapping: {}", name);

        String[] values = null;
        String value = null;
        try {
            loadACLProperties();
            value = aclProperties.getProperty(name);

        } catch (IOException e) {
            auditor.log(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    null,
                    null,
                    LOGGING_ACL_PARSING_ERROR + ":" + auditInfo));

            throw new PKIException(e);
        }

        // If no property defined, allow request.
        if (value == null) {
            logger.debug("ACLChecker: Unprotected resource; access granted");

            auditor.log(AuthzEvent.createSuccessEvent(
                    auditSubjectID,
                    null,
                    null,
                    LOGGING_NO_ACL_ACCESS_ALLOWED + ":" + auditInfo));

            return;
        }

        // accessing protected resource
        values = value.split(",");

        // If invalid mapping, reject request.
        if (values.length != 2) {
            logger.error("ACLChecker: Invalid ACL mapping: {}", value);

            auditor.log(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    null,
                    null,
                    LOGGING_INVALID_ACL_MAPPING + ":" + auditInfo));

            throw new ForbiddenException("Invalid ACL mapping.");
        }

        logger.debug("ACLChecker: ACL: {}", value);

        try {
            // Check authorization.
            AuthzToken authzToken = authzSubsystem.authorize(
                    authzMgrName,
                    authToken,
                    values[0],
                    values[1]);

            // If not authorized, reject request.
            if (authzToken == null) {
                String info = "No authorization token present.";
                logger.debug("ACLChecker: {}", info);

                auditor.log(AuthzEvent.createFailureEvent(
                        auditSubjectID,
                        values[0],
                        values[1],
                        info));

                throw new ForbiddenException("No authorization token present.");
            }

            logger.debug("ACLChecker: access granted");

        } catch (EAuthzAccessDenied e) {
            String info = e.getMessage();
            logger.debug("ACLChecker: {}", info);

            auditor.log(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    values[0],
                    values[1],
                    info));

            throw new ForbiddenException(e.toString());

        } catch (EBaseException e) {
            String info = e.getMessage();
            logger.error("ACLChecker: " + info, e);

            auditor.log(AuthzEvent.createFailureEvent(
                    auditSubjectID,
                    values[0],
                    values[1],
                    info));

            throw new PKIException(e);
        }

        logger.debug("ACLChecker: Protected resource; access granted");

        auditor.log(AuthzEvent.createSuccessEvent(
                auditSubjectID,
                values[0],
                values[1],
                auditInfo));

        // Log role assumption
        String[] roles = null;
        if (principal instanceof PKIPrincipal pkiPrincipal) {
            roles = pkiPrincipal.getRoles();
        } else if (principal instanceof PKIPrincipalCore corePrincipal) {
            roles = corePrincipal.getRoles();
        }
        if (roles != null) {
            auditor.log(RoleAssumeEvent.createSuccessEvent(
                    auditSubjectID,
                    String.join(",", roles)));
        }
    }

    /**
     * Extract an AuthToken from an external (non-PKI) principal.
     * Subclasses can override this for container-specific principal types.
     */
    protected AuthToken extractExternalAuthToken(Principal principal) {
        if (principal instanceof org.apache.catalina.realm.GenericPrincipal genPrincipal) {
            return new ExternalAuthToken(genPrincipal);
        }
        return null;
    }
}
