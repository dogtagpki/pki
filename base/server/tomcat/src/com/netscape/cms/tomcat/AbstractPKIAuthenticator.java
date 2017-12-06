// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.tomcat;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.catalina.Authenticator;
import org.apache.catalina.Container;
import org.apache.catalina.Globals;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SSLAuthenticator;
import org.apache.catalina.connector.Request;

/**
 * @author Endi S. Dewata
 */
public abstract class AbstractPKIAuthenticator extends AuthenticatorBase {

    final static Logger logger = Logger.getLogger(AbstractPKIAuthenticator.class.getName());

    public final static String BASIC_AUTHENTICATOR = "BASIC";
    public final static String FORM_AUTHENTICATOR = "FORM";

    String fallbackMethod = BASIC_AUTHENTICATOR;

    AuthenticatorBase sslAuthenticator = new SSLAuthenticator();
    AuthenticatorBase fallbackAuthenticator = new BasicAuthenticator();

    public AbstractPKIAuthenticator() {
        logger.info("PKIAuthenticator: Creating " + getClass().getSimpleName());
    }

    public String getFallbackMethod() {
        return fallbackMethod;
    }

    public void setFallbackMethod(String fallbackMethod) {
        logger.info("PKIAuthenticator: Fallback method: " + fallbackMethod);
        this.fallbackMethod = fallbackMethod;

        if (BASIC_AUTHENTICATOR.equalsIgnoreCase(fallbackMethod)) {
            fallbackAuthenticator = new BasicAuthenticator();

        } else if (FORM_AUTHENTICATOR.equalsIgnoreCase(fallbackMethod)) {
            fallbackAuthenticator = new FormAuthenticator();
        }

    }

    public boolean doAuthenticate(Request request, HttpServletResponse response) throws IOException {
        X509Certificate certs[] = (X509Certificate[]) request.getAttribute(Globals.CERTIFICATES_ATTR);
        boolean result;

        if (certs != null && certs.length > 0) {
            logger.info("PKIAuthenticator: Authenticate with client certificate authentication");
            HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response) {
                public void setHeader(String name, String value) {
                    logger.fine("PKIAuthenticator: SSL auth header: " + name + "=" + value);
                };
                public void sendError(int code) {
                    logger.fine("PKIAuthenticator: SSL auth return code: " + code);
                }
            };
            result = doSubAuthenticate(sslAuthenticator, request, wrapper);

        } else {
            logger.info("PKIAuthenticator: Authenticating with " + fallbackMethod + " authentication");
            HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response) {
                public void setHeader(String name, String value) {
                    logger.fine("PKIAuthenticator: Fallback auth header: " + name + "=" + value);
                };
                public void sendError(int code) {
                    logger.fine("PKIAuthenticator: Fallback auth return code: " + code);
                }
            };
            result = doSubAuthenticate(fallbackAuthenticator, request, wrapper);
        }

        if (result)
            return true;

        logger.info("PKIAuthenticator: Result: " + result);
        String realmName = doGetRealmName(request);
        response.setHeader(AUTH_HEADER_NAME,
            "Basic realm=\"" + (realmName == null ? REALM_NAME : realmName) + "\"");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);

        return false;
    }

    public abstract boolean doSubAuthenticate(
        Authenticator auth, Request req, HttpServletResponse resp)
        throws IOException;

    public abstract String doGetRealmName(Request req);


    @Override
    protected String getAuthMethod() {
        return HttpServletRequest.CLIENT_CERT_AUTH;
    };

    @Override
    public void setContainer(Container container) {
        logger.fine("PKIAuthenticator: Setting container");
        super.setContainer(container);
        sslAuthenticator.setContainer(container);
        fallbackAuthenticator.setContainer(container);
    }

    @Override
    protected void initInternal() throws LifecycleException {
        logger.fine("PKIAuthenticator: Initializing authenticators");

        super.initInternal();

        sslAuthenticator.setAlwaysUseSession(alwaysUseSession);
        sslAuthenticator.init();

        fallbackAuthenticator.setAlwaysUseSession(alwaysUseSession);
        fallbackAuthenticator.init();
    }

    @Override
    public void startInternal() throws LifecycleException {
        logger.fine("PKIAuthenticator: Starting authenticators");
        super.startInternal();
        sslAuthenticator.start();
        fallbackAuthenticator.start();
    }

    @Override
    public void stopInternal() throws LifecycleException {
        logger.fine("PKIAuthenticator: Stopping authenticators");
        super.stopInternal();
        sslAuthenticator.stop();
        fallbackAuthenticator.stop();
    }
}
