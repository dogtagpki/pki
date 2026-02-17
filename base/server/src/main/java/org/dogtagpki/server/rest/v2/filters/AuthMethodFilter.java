//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2.filters;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Comparator;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.MimeType;

import org.dogtagpki.server.rest.AuthMethodChecker;

/**
 * Basic Authentication Method filter for REST APIs
 *
 * Subclasses can associate AuthMethod to servlet, URLPatterns or specific endpoints. The {@link #setAuthMethod(String)} method will assign a
 * default AuthMethod to use for all the associated entities (servlet or pattern). To provide a finer grained AuthMethod it is possible to specify
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
    private String defaultAuthMethod;
    private Map<String, String> authMethodMap;
    private AuthMethodChecker authMethodChecker;

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
                AuthMethodChecker checker = getAuthMethodChecker();
                checker.checkAuthenticationMethod(req.getUserPrincipal(), authMethod);
                chain.doFilter(request, response);
             } catch (ForbiddenException fe) {
                 resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                 resp.setContentType(MimeType.APPLICATION_JSON);
                 PrintWriter out = resp.getWriter();
                 out.print(fe.getData().toJSON());
            }
        }
    }

    private synchronized AuthMethodChecker getAuthMethodChecker() {
        if (authMethodChecker == null) {
            String context = getServletContext().getContextPath();
            String subsystem = context.startsWith("/") ? context.substring(1) : context;
            authMethodChecker = new AuthMethodChecker(subsystem);
        }
        return authMethodChecker;
    }

    public void setAuthMethod(String authMethod) {
        this.defaultAuthMethod = authMethod;
    }

    public void setAuthMethodMap(Map<String, String> authMethodMap) {
        this.authMethodMap = authMethodMap;
    }
}
