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

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Locale;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;

import org.apache.catalina.realm.GenericPrincipal;
import org.jboss.resteasy.core.ResourceMethodInvoker;

import com.netscape.certsrv.authentication.ExternalAuthToken;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.UserInfo;

/**
 * @author Endi S. Dewata
 */
@Provider
public class SessionContextInterceptor implements ContainerRequestFilter {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SessionContextInterceptor.class);

    @Context
    HttpServletRequest servletRequest;

    @Context
    SecurityContext securityContext;

    public Locale getLocale(HttpServletRequest req) {
        String lang = req.getHeader("accept-language");

        if (lang == null)
            return Locale.getDefault();

        return new Locale(UserInfo.getUserLanguage(lang), UserInfo.getUserCountry(lang));
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {

        ResourceMethodInvoker methodInvoker = (ResourceMethodInvoker) requestContext
                .getProperty("org.jboss.resteasy.core.ResourceMethodInvoker");
        Method method = methodInvoker.getMethod();
        Class<?> clazz = methodInvoker.getResourceClass();

        logger.debug("SessionContextInterceptor: " + clazz.getSimpleName() + "." + method.getName() + "()");

        Principal principal = securityContext.getUserPrincipal();

        // If unauthenticated, ignore.
        if (principal == null) {
            logger.debug("SessionContextInterceptor: Not authenticated.");
            SessionContext.releaseContext();
            return;
        }

        logger.debug("SessionContextInterceptor: principal: " + principal.getName());

        IAuthToken authToken = null;

        if (principal instanceof PKIPrincipal)
            authToken = ((PKIPrincipal) principal).getAuthToken();
        else if (principal instanceof GenericPrincipal)
            authToken = new ExternalAuthToken((GenericPrincipal) principal);

        // If missing auth token, reject request.
        if (authToken == null) {
            logger.warn("SessionContextInterceptor: No authorization token present.");
            throw new ForbiddenException("No authorization token present.");
        }

        SessionContext context = SessionContext.getContext();

        String ip = servletRequest.getRemoteAddr();
        context.put(SessionContext.IPADDRESS, ip);

        Locale locale = getLocale(servletRequest);
        context.put(SessionContext.LOCALE, locale);

        context.put(SessionContext.AUTH_TOKEN, authToken);
        context.put(SessionContext.USER_ID, principal.getName());
        if (principal instanceof PKIPrincipal)
            context.put(SessionContext.USER, ((PKIPrincipal) principal).getUser());
    }
}
