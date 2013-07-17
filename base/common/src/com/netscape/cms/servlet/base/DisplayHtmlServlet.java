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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * This is the servlet that displays the html page for the corresponding input id.
 *
 * @version $Revision$, $Date$
 */
public class DisplayHtmlServlet extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = -4343458180370708327L;
    public final static String PROP_TEMPLATE = "template";
    public final static String PROP_HTML_PATH = "htmlPath";

    private String mHTMLPath = null;

    public DisplayHtmlServlet() {
        super();
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mHTMLPath = sc.getInitParameter(PROP_HTML_PATH);
        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    /**
     * Serves HTTP request.
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        CMS.debug("DisplayHtmlServlet about to service ");
        authenticate(cmsReq);
        try {
            String realpath =
                    mServletConfig.getServletContext().getRealPath("/" + mHTMLPath);

            if (realpath == null) {
                mLogger.log(
                        ILogger.EV_SYSTEM, ILogger.S_OTHER, ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSGW_NO_FIND_TEMPLATE", mHTMLPath));
                throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
            }
            File file = new File(realpath);
            long flen = file.length();
            byte[] bin = new byte[(int) flen];
            FileInputStream ins = new FileInputStream(file);

            int len = 0;
            if (ins.available() > 0) {
                len = ins.read(bin);
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(bin, 0, len);
            bos.writeTo(cmsReq.getHttpResp().getOutputStream());
            ins.close();
            bos.close();
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_OUT_TEMPLATE", mHTMLPath, e.toString()));
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
        }
    }
}
