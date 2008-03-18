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


import com.netscape.cms.servlet.common.*;

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.base.*;


/**
 * This servlet is started by the web server at startup, and
 * it starts the CMS framework.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class CMSStartServlet extends HttpServlet {
    public final static String PROP_CMS_CFG = "cfgPath";

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String path = config.getInitParameter(PROP_CMS_CFG);

        File f = new File(path);
        String old_path = "";
        if (!f.exists()) {
            int index = path.lastIndexOf("CS.cfg");
            if (index != -1) {
                old_path = path.substring(0, index)+"CMS.cfg";
            }
            File f1 = new File(old_path);
            if (f1.exists()) {
                boolean success = f1.renameTo(f);
                if (!success) {
                    String cmds[] = new String[3];
                    if (File.separator.equals("\\")) {
                        cmds[0] = "cmd";
                        cmds[1] = "/c";
                        cmds[2] = "copy "+
                          f1.getAbsolutePath().replace('/', '\\') + " " +
                          f.getAbsolutePath().replace('/', '\\');
                    } else {
                        cmds[0] = "/bin/sh";
                        cmds[1] = "-c";
                        cmds[2] = "cp " + f1.getAbsolutePath() + " " +
                          f.getAbsolutePath();
                    }

                    try {
                        Process process = Runtime.getRuntime().exec(cmds);
                        process.waitFor();
                    } catch (Exception e) {
                    }
                }
            }
        }
        try {
            CMS.start(path);
        } catch (EBaseException e) {
        }
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

    public void destroy() {
        CMS.shutdown();
        super.destroy();
    }
}
