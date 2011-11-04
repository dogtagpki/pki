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


public class ModuleServlet extends BaseServlet {

    /**
     * Collect information on where keys are to be generated.
     * Once collected, write to CS.cfg:
     *    "preop.module=soft"
     *      or
     *    "preop.module=hard"
     *
     * <ul>
     * <li>http.param selection "soft" or "hard" for software token or hardware token
     * </ul>
     */
    public Template process(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        Template template = null;

        CMS.debug("ModuleServlet: in ModuleServlet");
        try {

            // get the value of the selection
            String selection = request.getParameter("selection");

            if (selection != null) {

                if (selection.equals("soft")) {
                    CMS.debug("ModuleServlet: user selected software");
                    // XXX
                    CMS.getConfigStore().putString("preop.module", "soft");
                    CMS.getConfigStore().commit(false);
                    response.sendRedirect("size");
                } else if (selection.equals("hard")) {
                    CMS.debug("ModuleServlet: user selected hardware");
                    // YYY
                    CMS.getConfigStore().putString("preop.module", "hard");
                    CMS.getConfigStore().commit(false);
                    response.sendRedirect("size");
                } else {
                    CMS.debug("ModuleServlet: illegal selection: " + selection);
                    context.put("error", "failed selection");
                }
		
            } else {
                CMS.debug("ModuleServlet: no selection");
            }

            template = Velocity.getTemplate("admin/console/config/module.vm");
        } catch (Exception e) {
            CMS.debug("ModuleServlet: Exception caught: " + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }

        return template;
    }
}
