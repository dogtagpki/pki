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
import java.util.Locale;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.w3c.dom.Node;

import com.netscape.certsrv.base.SecurityDomainSessionTable;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.xml.XMLObject;

public class TokenAuthenticate extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TokenAuthenticate.class);

    private static final long serialVersionUID = -9098593390260940853L;
    private final static String SUCCESS = "0";

    public TokenAuthenticate() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    protected void process(CMSRequest cmsReq) throws Exception {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        CMSEngine engine = getCMSEngine();
        EngineConfig config = engine.getConfig();

        String sessionId = httpReq.getParameter("sessionID");
        logger.info("TokenAuthenticate: Authenticating session " + sessionId);

        if (StringUtils.isEmpty(sessionId)) {
            logger.error("TokenAuthenticate: Missing session ID");
            outputError(httpResp, "Missing session ID");
            return;
        }

        String givenHost = httpReq.getParameter("hostname");
        logger.debug("TokenAuthenticate: - client host: " + givenHost);

        if (StringUtils.isEmpty(givenHost)) {
            logger.error("TokenAuthenticate: Missing client host");
            outputError(httpResp, "Missing client host");
            return;
        }

        boolean checkIP = false;
        try {
            checkIP = config.getBoolean("securitydomain.checkIP", false);
        } catch (Exception e) {
        }

        logger.debug("TokenAuthenticate: Checking session table for session " + sessionId);
        SecurityDomainSessionTable table = engine.getSecurityDomainSessionTable();

        if (table == null) {
            logger.error("TokenAuthenticate: Missing session table");
            outputError(httpResp, "Internal error");
            return;
        }

        if (!table.sessionExists(sessionId)) {
            logger.error("TokenAuthenticate: Session not found: " + sessionId);
            outputError(httpResp, "Authentication failed");
            return;
        }

        logger.debug("TokenAuthenticate: Found session " + sessionId);
        if (checkIP) {
            String hostname = table.getIP(sessionId);
            logger.debug("TokenAuthenticate: - session host: " + hostname);

            if (!hostname.equals(givenHost)) {
                logger.error("TokenAuthenticate: Invalid client host: " + givenHost);
                outputError(httpResp, "Authentication failed");
                return;
            }
        }

        logger.debug("TokenAuthenticate: Session " + sessionId + " valid");
        String uid = table.getUID(sessionId);
        String gid = table.getGroup(sessionId);

        XMLObject xmlObj = new XMLObject();
        Node root = xmlObj.createRoot("XMLResponse");

        xmlObj.addItemToContainer(root, "Status", SUCCESS);
        xmlObj.addItemToContainer(root, "uid", uid);
        xmlObj.addItemToContainer(root, "gid", gid);

        byte[] cb = xmlObj.toByteArray();

        outputResult(httpResp, "application/xml", cb);
    }

    @Override
    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
    }

    /**
     * Retrieves locale based on the request.
     */
    @Override
    protected Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader("accept-language");

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                    UserInfo.getUserCountry(lang));
        }
        return locale;
    }
}
