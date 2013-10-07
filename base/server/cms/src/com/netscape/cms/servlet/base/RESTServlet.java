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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.servlet.base;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;

public class RESTServlet extends HttpServlet {

    private static final long serialVersionUID = -466592331169846158L;

    public void service(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        CMS.debug("RESTServlet: Attempt to access REST services using " + request.getRequestURI());
        CMS.debug("RESTServlet: sending 501 (not implemented)");

        String error =
            "The REST services are not available because this server is a legacy \n" +
            "Dogtag 9 server. To access the REST services this server must be \n" +
            "migrated into a new Dogtag 10 server.";

        response.sendError(HttpServletResponse.SC_NOT_IMPLEMENTED, error);
    }

}
