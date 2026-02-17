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
import java.util.Collection;
import java.util.HashSet;
import java.util.Properties;

import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.realm.PKIPrincipalCore;
import com.netscape.cmscore.apps.CMS;

/**
 * Container-agnostic authentication method checking logic.
 *
 * Extracts the business logic from AuthMethodFilter (which extends
 * HttpFilter) so it can be reused by both Tomcat servlet filters and
 * Quarkus ContainerRequestFilters.
 *
 * NOTE: This class will be moved to pki-server-core once its
 * dependencies are moved there.
 */
public class AuthMethodChecker {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthMethodChecker.class);

    private final String subsystem;
    private Properties authProperties;

    public AuthMethodChecker(String subsystem) {
        this.subsystem = subsystem;
    }

    /**
     * Load auth method properties from the default and instance-specific files.
     */
    public synchronized void loadAuthProperties() throws IOException {

        if (authProperties != null)
            return;

        authProperties = new Properties();

        // load default mapping
        Path defaultMappingAuth = Paths.get("/usr/share/pki", subsystem, "conf", "auth-method.properties");
        File defaultMapping = defaultMappingAuth.toFile();
        logger.debug("AuthMethodChecker: loading {}", defaultMapping);
        try (FileReader in = new FileReader(defaultMapping)) {
            authProperties.load(in);
        }

        // load custom mapping
        Path customMappingAuth = Paths.get(CMS.getInstanceDir(), subsystem, "conf", "auth-method.properties");
        File customMapping = customMappingAuth.toFile();
        logger.debug("AuthMethodChecker: checking {}", customMapping);
        if (customMapping.exists()) {
            logger.debug("AuthMethodChecker: loading {}", customMapping);
            try (FileReader in = new FileReader(customMapping)) {
                authProperties.load(in);
            }
        }
    }

    /**
     * Check that the authentication method used matches what is required.
     *
     * @param principal the authenticated principal (may be null)
     * @param authMethodName the authentication method mapping name
     * @throws ForbiddenException if the authentication method is not allowed
     */
    public void checkAuthenticationMethod(Principal principal, String authMethodName) throws ForbiddenException {

        String name = authMethodName == null ? "" : authMethodName;

        logger.debug("AuthMethodChecker: mapping: {}", name);

        try {
            loadAuthProperties();

            String value = authProperties.getProperty(name);
            Collection<String> authMethods = new HashSet<>();
            if (value != null) {
                for (String v : value.split(",")) {
                    authMethods.add(v.trim());
                }
            }

            logger.debug("AuthMethodChecker: required auth methods: {}", authMethods);

            // If unauthenticated, reject request.
            if (principal == null) {
                if (authMethods.isEmpty() || authMethods.contains("anonymous") || authMethods.contains("*")) {
                    logger.debug("AuthMethodChecker: anonymous access allowed");
                    return;
                }
                logger.error("AuthMethodChecker: anonymous access not allowed");
                throw new ForbiddenException("Anonymous access not allowed.");
            }

            AuthToken authToken = null;
            if (principal instanceof PKIPrincipal pkPrincipal) {
                authToken = pkPrincipal.getAuthToken();
            } else if (principal instanceof PKIPrincipalCore corePrincipal) {
                authToken = (AuthToken) corePrincipal.getAuthToken();
            } else {
                authToken = extractExternalAuthToken(principal);
            }

            // If missing auth token, reject request.
            if (authToken == null) {
                logger.error("AuthMethodChecker: missing authentication token");
                throw new ForbiddenException("Missing authentication token.");
            }

            String authManager = authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);

            logger.debug("AuthMethodChecker: authentication manager: {}", authManager);

            if (authManager == null) {
                logger.error("AuthMethodChecker: missing authentication manager");
                throw new ForbiddenException("Missing authentication manager.");
            }

            if (
                authMethods.isEmpty()
                || authManager.equals("external")
                || authMethods.contains(authManager)
                || authMethods.contains("*")
            ) {
                logger.debug("AuthMethodChecker: access granted");
                return;
            }

            throw new ForbiddenException("Authentication method not allowed.");

        } catch (IOException e) {
            throw new PKIException(e);
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
