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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;


import org.apache.velocity.Template;
import org.apache.velocity.servlet.VelocityServlet;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import javax.servlet.http.*;

import java.io.*;
import java.util.*;
import com.netscape.certsrv.apps.*;


public class BaseServlet extends VelocityServlet {

    /**
     * Returns usage of this servlet.
     */
    public String getUsage() {
        return null;
    }

    public boolean authenticate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        String pin = (String) request.getSession().getAttribute("pin");

        if (pin == null) {
            try {
                response.sendRedirect("login");
            } catch (IOException e) {}
            return false;
        }
        return true;
    }

    public void outputHttpParameters(HttpServletRequest httpReq) {
        CMS.debug("CMSServlet:serice() uri = " + httpReq.getRequestURI());
        Enumeration paramNames = httpReq.getParameterNames();

        while (paramNames.hasMoreElements()) {
            String pn = (String) paramNames.nextElement();

            CMS.debug(
                    "CMSServlet::service() param name='" + pn + "' value='"
                    + httpReq.getParameter(pn) + "'");
        }
    }

    /**
     * Processes request.
     */
    public Template process(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        return null;
    }

    public Template handleRequest(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        if (CMS.debugOn()) {
            outputHttpParameters(request);
        }

        /* XXX - authentication */
        if (!authenticate(request, response, context)) {
            return null;
        }

        /* XXX - authorization */

        return process(request, response, context);
    }
}
