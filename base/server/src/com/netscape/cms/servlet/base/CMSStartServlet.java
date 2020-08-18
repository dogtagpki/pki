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

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.common.Constants;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * This servlet is started by the web server at startup, and
 * it starts the CMS framework.
 *
 * @version $Revision$, $Date$
 */
public class CMSStartServlet extends HttpServlet {

    public static Logger logger = LoggerFactory.getLogger(CMSStartServlet.class);

    private static final long serialVersionUID = 515623839479425172L;
    public final static String PROP_CMS_ENGINE = "engine";

    public void init() throws ServletException {

        Class<?> engineClass = CMSEngine.class;

        String className = getServletConfig().getInitParameter(PROP_CMS_ENGINE);
        if (className != null) {
            try {
                logger.debug("CMSStartServlet: Loading CMS engine: " + className);
                engineClass = Class.forName(className);
            } catch (ClassNotFoundException e) {
                logger.error("Unable to load CMS engine: " + e.getMessage(), e);
                throw new ServletException(e);
            }
        }

        CMSEngine engine = null;

        try {
            logger.debug("CMSStartServlet: Creating CMS engine: " + engineClass.getName());
            engine = (CMSEngine) engineClass.newInstance();

            engine.start();

        } catch (Exception e) {
            logger.error("Unable to start CMS engine: " + e.getMessage(), e);
            logger.error(Constants.SERVER_SHUTDOWN_MESSAGE);

            if (engine != null) {
                engine.shutdown();
            }
            throw new ServletException(e);
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

    /**
     * This method will be called when Tomcat is shutdown.
     */
    public void destroy() {
        logger.debug("CMSStartServlet.destroy(): shutdown server");
        CMSEngine engine = CMS.getCMSEngine();
        engine.shutdown();
    }
}
