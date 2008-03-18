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


public abstract class ConfigBaseServlet extends BaseServlet {
    public boolean isDisplayMode(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        String display = request.getParameter("display");

        if (display == null) {
            return true;
        } else {
            return false;
        }
    }

    public abstract void display(HttpServletRequest request,
            HttpServletResponse response, Context context);

    public abstract void update(HttpServletRequest request, 
            HttpServletResponse response, Context context);

    public abstract Template getTemplate(HttpServletRequest request,
            HttpServletResponse response,
            Context context);

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
                                                                                
        if (CMS.debugOn()) {
            outputHttpParameters(request);
        }

        if (isDisplayMode(request, response, context)) {
            display(request, response, context);
        } else {
            update(request, response, context);
        }
                                                                                
        Template template = null;
                                                                                
        try {
            context.put("name", "Velocity Test");
            template = getTemplate(request, response, context);
        } catch (Exception e) {
            System.err.println("Exception caught: " + e.getMessage());
        }
                                                                                
        return template;
    }
}
