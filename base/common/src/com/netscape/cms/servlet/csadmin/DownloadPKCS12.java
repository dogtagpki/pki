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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.base.UserInfo;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ICMSTemplateFiller;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class DownloadPKCS12 extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -7770226137155537526L;
    private final static String AUTH_FAILURE = "2";

    public DownloadPKCS12() {
        super();
    }

    /**
     * initialize the servlet.
     *
     * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        CMS.debug("DownloadPKCS12: initializing...");
        super.init(sc);
        CMS.debug("DownloadPKCS12: done initializing...");
    }

    /**
     * Process the HTTP request.
     */
    protected void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("DownloadPKCS12: processing...");

        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();
        IConfigStore cs = CMS.getConfigStore();
        mRenderResult = false;

        // check the pin from the session
        String pin = (String) httpReq.getSession().getAttribute("pin");
        if (pin == null) {
            CMS.debug("DownloadPKCS12 process: Failed to get the pin from the cookie.");
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated",
                        null);
            return;
        }

        String cspin = "";
        try {
            cspin = cs.getString("preop.pin");
        } catch (Exception e) {
        }

        if (!pin.equals(cspin)) {
            CMS.debug("DownloadPKCS12 process: Wrong pin");
            outputError(httpResp, AUTH_FAILURE, "Error: Not authenticated",
                        null);
            return;
        }

        byte[] pkcs12 = null;
        try {
            String str = cs.getString("preop.pkcs12");
            pkcs12 = CryptoUtil.string2byte(str);
        } catch (Exception e) {
        }

        try {
            httpResp.setContentType("application/x-pkcs12");
            httpResp.getOutputStream().write(pkcs12);
            return;
        } catch (Exception e) {
            CMS.debug("DownloadPKCS12 process: Exception=" + e.toString());
        }
    }

    protected void setDefaultTemplates(ServletConfig sc) {
    }

    protected void renderTemplate(
            CMSRequest cmsReq, String templateName, ICMSTemplateFiller filler)
            throws IOException {// do nothing
    }

    protected void renderResult(CMSRequest cmsReq) throws IOException {// do nothing, ie, it will not return the default javascript.
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
}
