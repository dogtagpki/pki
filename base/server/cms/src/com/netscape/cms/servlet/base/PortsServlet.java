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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.w3c.dom.Node;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * This servlet returns port information.
 *
 * @version $Revision$, $Date$
 */
public class PortsServlet extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -3750153734073658934L;

    public PortsServlet() {
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override these to output directly ourselves.
        mTemplates.remove(ICMSRequest.SUCCESS);
        mTemplates.remove(ICMSRequest.ERROR);
    }

    /**
     * Serves HTTP request.
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        // process query if authentication is successful
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        String secure = req.getParameter("secure");
        String port = null;

        if (secure.equals("true"))
            port = CMS.getEESSLPort();
        else
            port = CMS.getEENonSSLPort();

        try {
            XMLObject xmlObj = null;
            xmlObj = new XMLObject();

            Node root = xmlObj.createRoot("XMLResponse");
            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            xmlObj.addItemToContainer(root, "Port", port);
            byte[] cb = xmlObj.toByteArray();
            outputResult(resp, "application/xml", cb);
        } catch (Exception e) {
            CMS.debug("Failed to send the XML output");
        }
    }

    protected void renderResult(CMSRequest cmsReq) throws IOException {
        // do nothing, ie, it will not return the default javascript.
    }
}
