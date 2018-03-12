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

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Authenticator;
import org.apache.catalina.connector.Request;

/**
 * @author Endi S. Dewata
 */
public class SSLAuthenticatorWithFallback extends AbstractPKIAuthenticator {

    @Override
    public boolean doSubAuthenticate(
            Authenticator auth, Request req, HttpServletResponse resp)
            throws IOException {
        return auth.authenticate(req, resp);
    }

    @Override
    public String doGetRealmName(Request request) {
        return getRealmName(request.getContext());
    }

    @Override
    public boolean authenticate(Request request, HttpServletResponse response) throws IOException {
        return doAuthenticate(request, response);
    }

}
