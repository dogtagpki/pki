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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.catalina.Container;
import org.apache.catalina.Globals;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SSLAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;

/**
 * @author Endi S. Dewata
 */
public class SSLAuthenticatorWithFallback extends AuthenticatorBase {

    public final static String BASIC_AUTHENTICATOR = "BASIC";
    public final static String FORM_AUTHENTICATOR = "FORM";

    String fallbackMethod = BASIC_AUTHENTICATOR;

    AuthenticatorBase sslAuthenticator = new SSLAuthenticator();
    AuthenticatorBase fallbackAuthenticator = new BasicAuthenticator();

    public SSLAuthenticatorWithFallback() {
        log("Creating SSL authenticator with fallback");
    }

    @Override
    public String getInfo() {
        return "SSL authenticator with "+fallbackMethod+" fallback.";
    }

    public String getFallbackMethod() {
        return fallbackMethod;
    }

    public void setFallbackMethod(String fallbackMethod) {
        log("Fallback method: "+fallbackMethod);
        this.fallbackMethod = fallbackMethod;

        if (BASIC_AUTHENTICATOR.equalsIgnoreCase(fallbackMethod)) {
            fallbackAuthenticator = new BasicAuthenticator();

        } else if (FORM_AUTHENTICATOR.equalsIgnoreCase(fallbackMethod)) {
            fallbackAuthenticator = new FormAuthenticator();
        }

    }

    @Override
    public boolean authenticate(Request request, HttpServletResponse response, LoginConfig config) throws IOException {

        X509Certificate certs[] = (X509Certificate[]) request.getAttribute(Globals.CERTIFICATES_ATTR);
        boolean result;

        if (certs != null && certs.length > 0) {
            log("Authenticate with client certificate authentication");
            HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response) {
                public void setHeader(String name, String value) {
                    log("SSL auth header: "+name+"="+value);
                };
                public void sendError(int code) {
                    log("SSL auth return code: "+code);
                }
            };
            result = sslAuthenticator.authenticate(request, wrapper, config);

        } else {
            log("Authenticating with "+fallbackMethod+" authentication");
            HttpServletResponseWrapper wrapper = new HttpServletResponseWrapper(response) {
                public void setHeader(String name, String value) {
                    log("Fallback auth header: "+name+"="+value);
                };
                public void sendError(int code) {
                    log("Fallback auth return code: "+code);
                }
            };
            result = fallbackAuthenticator.authenticate(request, wrapper, config);
        }

        if (result)
            return true;

        log("Result: "+result);

        StringBuilder value = new StringBuilder(16);
        value.append("Basic realm=\"");
        if (config.getRealmName() == null) {
            value.append(REALM_NAME);
        } else {
            value.append(config.getRealmName());
        }
        value.append('\"');
        response.setHeader(AUTH_HEADER_NAME, value.toString());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);

        return false;
    }

    @Override
    protected String getAuthMethod() {
        return HttpServletRequest.CLIENT_CERT_AUTH;
    };

    @Override
    public void setContainer(Container container) {
        log("Setting container");
        super.setContainer(container);
        sslAuthenticator.setContainer(container);
        fallbackAuthenticator.setContainer(container);
    }

    @Override
    protected void initInternal() throws LifecycleException {
        log("Initializing authenticators");

        super.initInternal();

        sslAuthenticator.setAlwaysUseSession(alwaysUseSession);
        sslAuthenticator.init();

        fallbackAuthenticator.setAlwaysUseSession(alwaysUseSession);
        fallbackAuthenticator.init();
    }

    @Override
    public void startInternal() throws LifecycleException {
        log("Starting authenticators");
        super.startInternal();
        sslAuthenticator.start();
        fallbackAuthenticator.start();
    }

    @Override
    public void stopInternal() throws LifecycleException {
        log("Stopping authenticators");
        super.stopInternal();
        sslAuthenticator.stop();
        fallbackAuthenticator.stop();
    }

    public void log(String message) {
        System.out.println("SSLAuthenticatorWithFallback: "+message);
    }
}
