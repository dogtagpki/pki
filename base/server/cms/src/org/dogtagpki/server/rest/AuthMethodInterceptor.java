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
package org.dogtagpki.server.rest;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Method;
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

import org.apache.catalina.realm.GenericPrincipal;
import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.spi.Failure;

import com.netscape.certsrv.authentication.AuthMethodMapping;
import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.cms.realm.PKIPrincipal;

/**
 * @author Endi S. Dewata
 */
@Provider
public class AuthMethodInterceptor implements ContainerRequestFilter {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(AuthMethodInterceptor.class);

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
        String defaultMapping = "/usr/share/pki/" + subsystem + "/conf/auth-method.properties";
        logger.debug("AuthMethodInterceptor: loading " + defaultMapping);
        try (FileReader in = new FileReader(defaultMapping)) {
            properties.load(in);
        }

        // load custom mapping
        File customMapping = new File(System.getProperty("catalina.base") +
                "/" + subsystem + "/conf/auth-method.properties");
        logger.debug("AuthMethodInterceptor: checking " + customMapping);
        if (customMapping.exists()) {
            logger.debug("AuthMethodInterceptor: loading " + customMapping);
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

        logger.debug("AuthMethodInterceptor: " + clazz.getSimpleName() + "." + method.getName() + "()");

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

        logger.debug("AuthMethodInterceptor: mapping: " + name);

        try {
            loadProperties();

            String value = properties.getProperty(name);
            Collection<String> authMethods = new HashSet<String>();
            if (value != null) {
                for (String v : value.split(",")) {
                    authMethods.add(v.trim());
                }
            }

            logger.debug("AuthMethodInterceptor: required auth methods: " + authMethods);

            Principal principal = securityContext.getUserPrincipal();

            // If unauthenticated, reject request.
            if (principal == null) {
                if (authMethods.isEmpty() || authMethods.contains("anonymous") || authMethods.contains("*")) {
                    logger.debug("AuthMethodInterceptor: anonymous access allowed");
                    return;
                }
                logger.error("AuthMethodInterceptor: anonymous access not allowed");
                throw new ForbiddenException("Anonymous access not allowed.");
            }

            IAuthToken authToken = null;
            if (principal instanceof PKIPrincipal)
                authToken = ((PKIPrincipal) principal).getAuthToken();
            else if (principal instanceof GenericPrincipal)
                authToken = new ExternalAuthToken((GenericPrincipal) principal);

            // If missing auth token, reject request.
            if (authToken == null) {
                logger.error("AuthMethodInterceptor: missing authentication token");
                throw new ForbiddenException("Missing authentication token.");
            }

            String authManager = authToken.getInString(IAuthToken.TOKEN_AUTHMGR_INST_NAME);

            logger.debug("AuthMethodInterceptor: authentication manager: " + authManager);

            if (authManager == null) {
                logger.error("AuthMethodInterceptor: missing authentication manager");
                throw new ForbiddenException("Missing authentication manager.");
            }

            if (
                authMethods.isEmpty()
                || authManager.equals("external")
                || authMethods.contains(authManager)
                || authMethods.contains("*")
            ) {
                logger.debug("AuthMethodInterceptor: access granted");
                return;
            }

            throw new ForbiddenException("Authentication method not allowed.");

        } catch (IOException e) {
            e.printStackTrace();
            throw new Failure(e);
        }
    }
}
