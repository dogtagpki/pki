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

public class ConfigImportCertServlet extends BaseServlet {

    /**
     *
     */
    private static final long serialVersionUID = 1907102921734394118L;

    public Template process(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        Template template = null;

        try {
            context.put("name", "Velocity Test");
            template = Velocity.getTemplate(
                    "admin/console/config/config_importcert.vm");
        } catch (Exception e) {
            System.err.println("Exception caught: " + e.getMessage());
        }

        return template;
    }
}
