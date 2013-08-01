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
//(C) 2013 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.cms.authorization;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;

import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.spi.Failure;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.cms.realm.PKIPrincipal;

/**
 * @author Endi S. Dewata
 */
@Provider
public class AuthMethodInterceptor implements ContainerRequestFilter {

    Properties authProperties;

    @Context
    ServletContext servletContext;

    @Context
    SecurityContext securityContext;

    public synchronized void loadAuthProperties() throws IOException {

        if (authProperties != null)
            return;

        authProperties = new Properties();

        URL url = servletContext.getResource("/WEB-INF/auth-method.properties");

        if (url == null) {
            authProperties.put("default", "*");
            authProperties.put("account", "certUserDBAuthMgr,passwdUserDBAuthMgr");
            authProperties.put("admin", "certUserDBAuthMgr");
            authProperties.put("agent", "certUserDBAuthMgr");
            authProperties.put("profiles", "certUserDBAuthMgr");
            authProperties.put("securityDomain.installToken", "passwdUserDBAuthMgr");
        } else {
            authProperties.load(url.openStream());
        }
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        ResourceMethodInvoker methodInvoker = (ResourceMethodInvoker) requestContext
                .getProperty("org.jboss.resteasy.core.ResourceMethodInvoker");
        Method method = methodInvoker.getMethod();
        Class<?> clazz = methodInvoker.getResourceClass();

        CMS.debug("AuthMethodInterceptor: " + clazz.getSimpleName() + "." + method.getName() + "()");

        // Get authentication mapping for the method.
        AuthMethodMapping authMapping = method.getAnnotation(AuthMethodMapping.class);

        // If not available, get authentication mapping for the class.
        if (authMapping == null) {
            authMapping = clazz.getAnnotation(AuthMethodMapping.class);
        }

        String name;
        if (authMapping == null) {
            // If not available, use the default mapping.
            name = "default";
        } else {
            // Get the method label
            name = authMapping.value();
        }

        CMS.debug("AuthMethodInterceptor: mapping name: " + name);

        try {
            loadAuthProperties();

            String value = authProperties.getProperty(name);
            Collection<String> authMethods = new HashSet<String>();
            if (value != null) {
                for (String v : value.split(",")) {
                    authMethods.add(v.trim());
                }
            }

            CMS.debug("AuthMethodInterceptor: required auth methods: " + authMethods);

            Principal principal = securityContext.getUserPrincipal();

            // If unauthenticated, reject request.
            if (principal == null) {
                if (authMethods.isEmpty() || authMethods.contains("anonymous") || authMethods.contains("*")) {
                    CMS.debug("AuthMethodInterceptor: anonymous access allowed");
                    return;
                }
                CMS.debug("AuthMethodInterceptor: anonymous access not allowed");
                throw new ForbiddenException("Anonymous access not allowed.");
            }

            // If unrecognized principal, reject request.
            if (!(principal instanceof PKIPrincipal)) {
                CMS.debug("AuthMethodInterceptor: unknown principal");
                throw new ForbiddenException("Unknown user principal");
            }

            PKIPrincipal pkiPrincipal = (PKIPrincipal) principal;
            IAuthToken authToken = pkiPrincipal.getAuthToken();

            // If missing auth token, reject request.
            if (authToken == null) {
                CMS.debug("AuthMethodInterceptor: missing authentication token");
                throw new ForbiddenException("Missing authentication token.");
            }

            String authManager = (String) authToken.get(AuthToken.TOKEN_AUTHMGR_INST_NAME);
            CMS.debug("AuthMethodInterceptor: authentication manager: " + authManager);

            if (authManager == null) {
                CMS.debug("AuthMethodInterceptor: missing authentication manager");
                throw new ForbiddenException("Missing authentication manager.");
            }

            if (authMethods.isEmpty() || authMethods.contains(authManager) || authMethods.contains("*")) {
                CMS.debug("AuthMethodInterceptor: " + authManager + " allowed");
                return;
            }

            throw new ForbiddenException("Authentication method not allowed.");

        } catch (IOException e) {
            e.printStackTrace();
            throw new Failure(e);
        }
    }
}
