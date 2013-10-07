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

import java.net.URL;
import java.net.URLDecoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;

public class SecurityDomainLogin extends BaseServlet {

    /**
     *
     */
    private static final long serialVersionUID = -1616344299101179396L;

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
            String url = request.getParameter("url");
            url = URLDecoder.decode(url, "UTF-8");
            URL u = null;
            if (url != null) {
                u = new URL(url);
            }
            int index = url.indexOf("subsystem=");
            String subsystem = "";
            if (index > 0) {
                subsystem = url.substring(index + 10);
                int index1 = subsystem.indexOf("&");
                if (index1 > 0)
                    subsystem = subsystem.substring(0, index1);
            }
            context.put("sd_uid", "");
            context.put("sd_pwd", "");
            context.put("url", url);
            context.put("host", u.getHost());
            context.put("errorString", "");
            context.put("sdhost", CMS.getEESSLHost());
            if (subsystem.equals("KRA")) {
                subsystem = "DRM";
            }
            context.put("subsystem", subsystem);
            // The "securitydomain.name" property ONLY resides in the "CS.cfg"
            // associated with the CS subsystem hosting the security domain.
            IConfigStore cs = CMS.getConfigStore();
            String sdname = cs.getString("securitydomain.name", "");
            context.put("name", sdname);
            template = Velocity.getTemplate("admin/console/config/securitydomainloginpanel.vm");
        } catch (Exception e) {
            System.err.println("Exception caught: " + e.getMessage());
        }

        return template;
    }
}
