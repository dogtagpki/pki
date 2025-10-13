//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2.filters;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Map;
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
import com.netscape.certsrv.base.MimeType;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.apps.CMS;

/**
 * Basic Authentication Method filter for REST APIs
 *
 * Subclasses can associate AuthMehtod to servlet, URLPatterns or specific endpoints. The {@link #setAuthMethod(String)} method will assign a
 * default AuthMehtod to use for all the associated entities (servlet or pattern). To provide a finer grained AuthMehtod it is possible to specify
 * a map with the method {@link #setAuthMethodMap(Map)}. The map value is the ACL to use while the key is the endpoint where
 * the ACL has to be applied. The key formal is:
 *
 *    key= <method>:<path>
 *
 * The method is one of the HTTP method as defined in Java servlet request (e.g. GET, POST, etc.).
 * The path is the endpoint in the associated servlet where the ACL has to be applied. If there is a REST path param this can be indicated
 * with the sequence "{}".
 *
 * Example of ACL a servlet handking token could be:
 *
 *   default authMethod: token.read
 *
 *   authMethodMap:
 *
 *   key= POST:token       value=token.add
 *   key= PUT:token/{}     value=token.modify
 *   key= DELETE:token/{}  value=token.delete
 *
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public abstract class AuthMethodFilter extends HttpFilter {

    private static final long serialVersionUID = 1L;
    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthMethodFilter.class);
    private Properties authProperties;
    private String defaultAuthMethod;
    private Map<String, String> authMethodMap;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        String method;
        String path;
        String authMethod = defaultAuthMethod;
        if(request instanceof HttpServletRequest req &&
                response instanceof HttpServletResponse resp) {
            method = req.getMethod();
            path = req.getPathInfo() != null ? req.getPathInfo().substring(1) : "";
            final String authMethodSearch = method + ":" + path;
            if (authMethodMap!=null) {
                String autMethodKey = authMethodMap.keySet().stream().
                        filter( key -> {
                            String keyRegex = key.replace("{}", "([^/]+)");
                            return authMethodSearch.matches(keyRegex);
                        } ).
                        sorted(Comparator.naturalOrder()).
                        findFirst().
                        orElse(null);
                if (autMethodKey != null) {
                    authMethod = authMethodMap.get(autMethodKey);
                }
            }
            try {
                logger.debug("AuthMethodFilter: Checking {}", authMethod);
                checkAuthenticationMethod(req, authMethod);
                chain.doFilter(request, response);
             } catch (ForbiddenException fe) {
                 resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                 resp.setContentType(MimeType.APPLICATION_JSON);
                 PrintWriter out = resp.getWriter();
                 out.print(fe.getData().toJSON());
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
        this.defaultAuthMethod = authMethod;
    }

    public void setAuthMethodMap(Map<String, String> authMethodMap) {
        this.authMethodMap = authMethodMap;
    }
}
