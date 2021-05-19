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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmsutil.xml.XMLObject;

public class GetStatus extends CMSServlet {

    public final static Logger logger = LoggerFactory.getLogger(GetStatus.class);

    private static final long serialVersionUID = -2852842030221659847L;

    public GetStatus() {
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
    protected void process(CMSRequest cmsReq) throws EBaseException {

        logger.debug("GetStatus: process()");

        HttpServletResponse httpResp = cmsReq.getHttpResp();
        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig config = engine.getConfig();

        int state = config.getState();
        String type = config.getType();
        String status = engine.isReady() ? "running" : "starting";
        String version = GetStatus.class.getPackage().getImplementationVersion();

        try {
            XMLObject xmlObj = null;

            xmlObj = new XMLObject();

            Node root = xmlObj.createRoot("XMLResponse");

            xmlObj.addItemToContainer(root, "State", state + "");
            xmlObj.addItemToContainer(root, "Type", type);
            xmlObj.addItemToContainer(root, "Status", status);
            xmlObj.addItemToContainer(root, "Version", version);

            String productName = CMS.getProductName();

            if (!StringUtils.isEmpty(productName)) {
                xmlObj.addItemToContainer(root, "ProductVersion", productName);
            }

            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);

        } catch (Exception e) {
            logger.warn("GetStatus: Failed to send the XML output: " + e, e);
        }
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
