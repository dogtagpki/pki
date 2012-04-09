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
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Node;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmsutil.xml.XMLObject;

public class GetTokenInfo extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -8416582986909026263L;
    private final static String SUCCESS = "0";

    public GetTokenInfo() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        CMS.debug("GetTokenInfo init");
    }

    /**
     * Process the HTTP request.
     * <ul>
     * <li>http.param op 'downloadBIN' - return the binary certificate chain
     * <li>http.param op 'displayIND' - display pretty-print of certificate chain components
     * </ul>
     *
     * @param cmsReq the object holding the request and response information
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        XMLObject xmlObj = null;
        try {
            xmlObj = new XMLObject();
        } catch (Exception e) {
            CMS.debug("GetTokenInfo process: Exception: " + e.toString());
            throw new EBaseException(e.toString());
        }

        Node root = xmlObj.createRoot("XMLResponse");

        IConfigStore config = CMS.getConfigStore();

        String certlist = "";
        try {
            certlist = config.getString("cloning.list");
        } catch (Exception e) {
        }

        StringTokenizer t1 = new StringTokenizer(certlist, ",");
        while (t1.hasMoreTokens()) {
            String name = t1.nextToken();
            if (name.equals("sslserver"))
                continue;
            name = "cloning." + name + ".nickname";
            String value = "";

            try {
                value = config.getString(name);
            } catch (Exception ee) {
                continue;
            }

            Node container = xmlObj.createContainer(root, "Config");
            xmlObj.addItemToContainer(container, "name", name);
            xmlObj.addItemToContainer(container, "value", value);
        }

        String value = "";
        String name = "cloning.module.token";
        try {
            value = config.getString(name);
        } catch (Exception e) {
        }

        Node container = xmlObj.createContainer(root, "Config");
        xmlObj.addItemToContainer(container, "name", name);
        xmlObj.addItemToContainer(container, "value", value);

        try {
            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            byte[] cb = xmlObj.toByteArray();

            outputResult(httpResp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("Failed to send the XML output");
        }
    }

    /**
     * Retrieves locale based on the request.
     */
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

    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
    }
}
