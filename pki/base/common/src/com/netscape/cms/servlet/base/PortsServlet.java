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
import java.net.*;
import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.cmsutil.xml.*;
import com.netscape.cmsutil.http.*;
import org.xml.sax.*;
import org.w3c.dom.*;

/**
 * This servlet returns port information.
 *
 * @version $Revision$, $Date$
 */
public class PortsServlet extends CMSServlet {

    private final static String INFO = "ports";

    public PortsServlet() {
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override these to output directly ourselves. 
        mTemplates.remove(CMSRequest.SUCCESS);
        mTemplates.remove(CMSRequest.ERROR);
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
