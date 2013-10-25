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
package com.netscape.cms.servlet.base;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.realm.PKIRealm;
import com.netscape.cms.tomcat.ProxyRealm;
import com.netscape.cmsutil.util.Utils;

/**
 * This servlet is started by the web server at startup, and
 * it starts the CMS framework.
 *
 * @version $Revision$, $Date$
 */
public class CMSStartServlet extends HttpServlet {
    /**
     *
     */
    private static final long serialVersionUID = 515623839479425172L;
    public final static String PROP_CMS_CFG = "cfgPath";

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String path = config.getInitParameter(PROP_CMS_CFG);

        File f = new File(path);
        String old_path = "";
        if (!f.exists()) {
            int index = path.lastIndexOf("CS.cfg");
            if (index != -1) {
                old_path = path.substring(0, index) + "CMS.cfg";
            }
            File f1 = new File(old_path);
            if (f1.exists()) {
                // The following block of code moves "CMS.cfg" to "CS.cfg".
                try {
                    if (Utils.isNT()) {
                        // NT is very picky on the path
                        Utils.exec("copy " +
                                    f1.getAbsolutePath().replace('/', '\\') +
                                    " " +
                                    f.getAbsolutePath().replace('/', '\\'));
                    } else {
                        // Create a copy of the original file which
                        // preserves the original file permissions.
                        Utils.exec("cp -p " + f1.getAbsolutePath() + " " +
                                    f.getAbsolutePath());
                    }

                    // Remove the original file if and only if
                    // the backup copy was successful.
                    if (f.exists()) {
                        if (!f1.delete()) {
                            CMS.debug("CMSStartServlet: init: Cannot delete file : " + old_path);
                        }

                        // Make certain that the new file has
                        // the correct permissions.
                        if (!Utils.isNT()) {
                            Utils.exec("chmod 00660 " + f.getAbsolutePath());
                        }
                    }
                } catch (Exception e) {
                }
            }
        }

        try {
            CMS.start(path);
        } catch (EBaseException e) {
        }

        // Register realm for this subsystem
        String context = getServletContext().getContextPath();
        if (context.startsWith("/")) context = context.substring(1);
        ProxyRealm.registerRealm(context, new PKIRealm());
    }

    public void doGet(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        res.setContentType("text/html");

        PrintWriter out = res.getWriter();

        out.print("<html>");
        out.print("<head><title>CMS is started!</title></head>");
        out.print("<body>");
        out.print("<h1>CMS is started!</h1>");
        out.print("</body></html>");
    }

    public String getServletInfo() {
        return "CMS startup servlet";
    }

    /**
     * This method will be called when Tomcat is shutdown.
     */
    public void destroy() {
        CMS.shutdown();
        super.destroy();
    }
}
