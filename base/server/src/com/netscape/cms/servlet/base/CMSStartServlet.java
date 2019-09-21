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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.server.PKIServerSocketListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.common.Constants;
import com.netscape.cms.realm.PKIRealm;
import com.netscape.cms.tomcat.ProxyRealm;
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
    public final static String PROP_CMS_CFG = "cfgPath";
    public final static String PROP_CMS_ENGINE = "engine";

    public void init() throws ServletException {

        // get web application context: /<subsystem>
        String context = getServletContext().getContextPath();

        // get subsystem name by removing the / prefix from the context
        String subsystem = context.startsWith("/") ? context.substring(1) : context;

        // get config path from web.xml
        String path = getServletConfig().getInitParameter(PROP_CMS_CFG);

        // if path not specified, use default path
        if (path == null) {
            // catalina.base points to instance dir
            // it's defined as CATALINA_BASE in <instance>/conf/tomcat.conf
            String instanceDir = System.getProperty("catalina.base");

            // path: <instance>/conf/<subsystem>/CS.cfg
            path = instanceDir + File.separator + "conf" + File.separator +
                    subsystem + File.separator + "CS.cfg";
        }

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

        } catch (Exception e) {
            logger.error("Unable to create CMS engine: " + e.getMessage(), e);
            throw new ServletException(e);
        }

        try {
            logger.debug("CMSStartServlet: Loading CMS engine configuration: " + path);
            engine.loadConfig(path);

        } catch (Exception e) {
            logger.error("Unable to load CMS engine configuration: " + e.getMessage(), e);
            throw new ServletException(e);
        }

        CMS.setCMSEngine(engine);

        try {
            logger.debug("CMSStartServlet: Starting CMS engine: " + engineClass.getName());
            engine.init(null, null);
            engine.startup();

        } catch (Exception e) {
            logger.error("Unable to start CMS engine: " + e.getMessage(), e);
            logger.error(Constants.SERVER_SHUTDOWN_MESSAGE);

            if (engine != null) {
                engine.shutdown();
            }
            throw new ServletException(e);
        }

        // Register realm for this subsystem
        ProxyRealm.registerRealm(subsystem, new PKIRealm());

        // Register TomcatJSS socket listener
        TomcatJSS tomcatJss = TomcatJSS.getInstance();
        tomcatJss.addSocketListener(new PKIServerSocketListener());
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
