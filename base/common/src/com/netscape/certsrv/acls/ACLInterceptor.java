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
package com.netscape.certsrv.acls;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URL;
import java.security.Principal;
import java.util.Properties;

import javax.servlet.ServletContext;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;

import org.jboss.resteasy.annotations.interception.Precedence;
import org.jboss.resteasy.annotations.interception.ServerInterceptor;
import org.jboss.resteasy.core.ResourceMethod;
import org.jboss.resteasy.core.ServerResponse;
import org.jboss.resteasy.spi.Failure;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.interception.PreProcessInterceptor;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.realm.PKIPrincipal;


/**
 * @author Endi S. Dewata
 */
@Provider
@ServerInterceptor
@Precedence("SECURITY")
public class ACLInterceptor implements PreProcessInterceptor {

    Properties authProperties;

    @Context
    ServletContext servletContext;

    @Context
    SecurityContext securityContext;

    public synchronized void loadAuthProperties() throws IOException {

        if (authProperties != null) return;

        URL url = servletContext.getResource("/WEB-INF/auth.properties");
        authProperties = new Properties();
        authProperties.load(url.openStream());
    }

    @Override
    public ServerResponse preProcess(
            HttpRequest request,
            ResourceMethod resourceMethod
        ) throws Failure, WebApplicationException {

        // Get ACL mapping for the method.
        Method method = resourceMethod.getMethod();
        ACLMapping aclMapping = method.getAnnotation(ACLMapping.class);

        // If not available, get ACL mapping for the class.
        if (aclMapping == null) {
            Class<?> clazz = method.getDeclaringClass();
            aclMapping = clazz.getAnnotation(ACLMapping.class);
        }

        // If still not available, it's unprotected, allow request.
        if (aclMapping == null) return null;

        Principal principal = securityContext.getUserPrincipal();

        // If unauthenticated, reject request.
        if (principal == null) {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        }

        // If unrecognized principal, reject request.
        if (!(principal instanceof PKIPrincipal)) {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        }

        PKIPrincipal pkiPrincipal = (PKIPrincipal)principal;
        IAuthToken authToken = pkiPrincipal.getAuthToken();

        // If missing auth token, reject request.
        if (authToken == null) {
            throw new WebApplicationException(Response.Status.FORBIDDEN);
        }

        try {
            loadAuthProperties();

            String name = aclMapping.value();
            String value = authProperties.getProperty(name);

            // If no property defined, allow request.
            if (value == null) return null;

            String values[] = value.split(",");

            // If invalid mapping, reject request.
            if (values.length != 2) {
                throw new WebApplicationException(Response.Status.FORBIDDEN);
            }

            // Check authorization.
            IAuthzSubsystem mAuthz = (IAuthzSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTHZ);
            AuthzToken authzToken = mAuthz.authorize(
                    "DirAclAuthz",
                    authToken,
                    values[0], // resource
                    values[1]); // operation

            // If not authorized, reject request.
            if (authzToken == null) {
                throw new WebApplicationException(Response.Status.FORBIDDEN);
            }

        } catch (EAuthzAccessDenied e) {
            throw new WebApplicationException(Response.Status.FORBIDDEN);

        } catch (IOException|EBaseException e) {
            e.printStackTrace();
            throw new Failure(e);
        }

        // Allow request.
        return null;
    }
}
