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
import java.lang.ThreadLocal;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Authenticator;
import org.apache.catalina.connector.Request;
import org.apache.catalina.deploy.LoginConfig;

/**
 * @author Endi S. Dewata
 */
public class SSLAuthenticatorWithFallback extends AbstractPKIAuthenticator {

    protected static final ThreadLocal<LoginConfig> loginConfig =
        new ThreadLocal<>();

    @Override
    public String getInfo() {
        return "SSL authenticator with "+fallbackMethod+" fallback.";
    }

    @Override
    public boolean doSubAuthenticate(
            Authenticator auth, Request req, HttpServletResponse resp)
            throws IOException {
        return auth.authenticate(req, resp, loginConfig.get());
    }

    @Override
    public String doGetRealmName(Request request /* ignored */) {
        return loginConfig.get().getRealmName();
    }

    @Override
    public boolean authenticate(Request request, HttpServletResponse response, LoginConfig config) throws IOException {
        loginConfig.set(config);
        try {
            return doAuthenticate(request, response);
        } finally {
            loginConfig.remove();
        }
    }

}
