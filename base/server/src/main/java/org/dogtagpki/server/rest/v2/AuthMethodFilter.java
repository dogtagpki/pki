//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Properties;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.catalina.realm.GenericPrincipal;
import org.dogtagpki.server.authentication.AuthToken;

import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.apps.CMS;

public abstract class AuthMethodFilter extends HttpFilter {

    private static final long serialVersionUID = 1L;
    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthMethodFilter.class);
    private Properties authProperties;
    private String authMethod;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if(request instanceof HttpServletRequest req &&
                response instanceof HttpServletResponse resp) {
            try {
                checkAuthenticationMethod(req, authMethod);
                chain.doFilter(request, response);
             } catch (ForbiddenException fe) {
                resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
    }

    private synchronized void loadAuthProperties() throws IOException {
        if (authProperties != null)
            return;

        authProperties = new Properties();
        String context = getServletContext().getContextPath();
        String subsystem = context.startsWith("/") ? context.substring(1) : context;

        // load default mapping
        Path defaultMappingAuth = Paths.get("/usr/share/pki", subsystem, "conf", "auth-method.properties");
        File defaultMapping = defaultMappingAuth.toFile();
        logger.debug("AuthMethodFilter: loading {}", defaultMapping);
        try (FileReader in = new FileReader(defaultMapping)) {
            authProperties.load(in);
        }

        // load custom mapping
        Path customMappingAuth = Paths.get(CMS.getInstanceDir(), subsystem, "conf", "auth-method.properties");
        File customMapping = customMappingAuth.toFile();
        logger.debug("AuthMethodFilter: checking {}", customMapping);
        if (customMapping.exists()) {
            logger.debug("AuthMethodFilter: loading {}", customMapping);
            try (FileReader in = new FileReader(customMapping)) {
                authProperties.load(in);
            }
        }
    }

    protected void checkAuthenticationMethod(HttpServletRequest request, String authMethName) throws ForbiddenException {
        String name = authMethName == null ? "" : authMethName;

        logger.debug("AuthMethodFilter: mapping: {}", name);

        try {
            loadAuthProperties();

            String value = authProperties.getProperty(name);
            Collection<String> authMethods = new HashSet<>();
            if (value != null) {
                for (String v : value.split(",")) {
                    authMethods.add(v.trim());
                }
            }

            logger.debug("AuthMethodFilter: required auth methods: {}", authMethods);

            Principal principal = request.getUserPrincipal();

            // If unauthenticated, reject request.
            if (principal == null) {
                if (authMethods.isEmpty() || authMethods.contains("anonymous") || authMethods.contains("*")) {
                    logger.debug("AuthMethodFilter: anonymous access allowed");
                    return;
                }
                logger.error("AuthMethodFilter: anonymous access not allowed");
                throw new ForbiddenException("Anonymous access not allowed.");
            }

            AuthToken authToken = null;
            if (principal instanceof PKIPrincipal pkPrincipal)
                authToken = pkPrincipal.getAuthToken();
            else if (principal instanceof GenericPrincipal genPrincipal)
                authToken = new ExternalAuthToken(genPrincipal);

            // If missing auth token, reject request.
            if (authToken == null) {
                logger.error("AuthMethodFilter: missing authentication token");
                throw new ForbiddenException("Missing authentication token.");
            }

            String authManager = authToken.getInString(AuthToken.TOKEN_AUTHMGR_INST_NAME);

            logger.debug("AuthMethodFilter: authentication manager: {}", authManager);

            if (authManager == null) {
                logger.error("AuthMethodFilter: missing authentication manager");
                throw new ForbiddenException("Missing authentication manager.");
            }

            if (
                authMethods.isEmpty()
                || authManager.equals("external")
                || authMethods.contains(authManager)
                || authMethods.contains("*")
            ) {
                logger.debug("AuthMethodFilter: access granted");
                return;
            }

            throw new ForbiddenException("Authentication method not allowed.");

        } catch (IOException e) {
            throw new PKIException(e);
        }
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }
}
