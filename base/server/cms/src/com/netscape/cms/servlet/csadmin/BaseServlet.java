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

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.context.Context;
import org.apache.velocity.servlet.VelocityServlet;

import com.netscape.certsrv.apps.CMS;

@SuppressWarnings("deprecation")
public class BaseServlet extends VelocityServlet {

    /**
     *
     */
    private static final long serialVersionUID = 3169697149104780149L;

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
            } catch (IOException e) {
            }
            return false;
        }
        return true;
    }

    public void outputHttpParameters(HttpServletRequest httpReq) {
        CMS.debug("BaseServlet:service() uri = " + httpReq.getRequestURI());
        Enumeration<String> paramNames = httpReq.getParameterNames();

        while (paramNames.hasMoreElements()) {
            String pn = paramNames.nextElement();
            // added this facility so that password can be hidden,
            // all sensitive parameters should be prefixed with
            // __ (double underscores); however, in the event that
            // a security parameter slips through, we perform multiple
            // additional checks to insure that it is NOT displayed
            if (pn.startsWith("__") ||
                    pn.endsWith("password") ||
                    pn.endsWith("passwd") ||
                    pn.endsWith("pwd") ||
                    pn.equalsIgnoreCase("admin_password_again") ||
                    pn.equalsIgnoreCase("directoryManagerPwd") ||
                    pn.equalsIgnoreCase("bindpassword") ||
                    pn.equalsIgnoreCase("bindpwd") ||
                    pn.equalsIgnoreCase("passwd") ||
                    pn.equalsIgnoreCase("password") ||
                    pn.equalsIgnoreCase("pin") ||
                    pn.equalsIgnoreCase("pwd") ||
                    pn.equalsIgnoreCase("pwdagain") ||
                    pn.equalsIgnoreCase("uPasswd")) {
                CMS.debug("BaseServlet::service() param name='" + pn +
                         "' value='(sensitive)'");
            } else {
                CMS.debug("BaseServlet::service() param name='" + pn +
                         "' value='" + httpReq.getParameter(pn) + "'");
            }
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
