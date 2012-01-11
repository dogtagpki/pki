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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;

public class LoginServlet extends BaseServlet {

    /**
     *
     */
    private static final long serialVersionUID = -4766622132710080340L;

    public boolean authenticate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        return true;
    }

    public Template process(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        Template template = null;

        try {
            String pin = request.getParameter("pin");

            if (pin == null) {
                context.put("error", "");
            } else {
                String cspin = CMS.getConfigStore().getString("preop.pin");

                if (cspin != null && cspin.equals(pin)) {
                    // create session
                    request.getSession(true).setAttribute("pin", cspin);
                    // pin match, redirect to the welcome page
                    response.sendRedirect("wizard");
                    return null;
                } else {
                    context.put("error", "Login Failed");
                }
            }
            template = Velocity.getTemplate("admin/console/config/login.vm");
        } catch (Exception e) {
            System.err.println("Exception caught: " + e.getMessage());
        }

        return template;
    }
}
