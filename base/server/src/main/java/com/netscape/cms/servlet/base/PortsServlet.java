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

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmsutil.json.JSONObject;

/**
 * This servlet returns port information.
 *
 * @version $Revision$, $Date$
 */
public class PortsServlet extends CMSServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PortsServlet.class);

    private static final long serialVersionUID = -3750153734073658934L;

    public PortsServlet() {
    }

    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override these to output directly ourselves.
        mTemplates.remove(CMSRequest.SUCCESS);
        mTemplates.remove(CMSRequest.ERROR);
    }

    /**
     * Serves HTTP request.
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {
        // process query if authentication is successful
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        CMSEngine engine = getCMSEngine();

        String secure = req.getParameter("secure");
        String port = null;

        if (secure.equals("true"))
            port = engine.getEESSLPort();
        else
            port = engine.getEENonSSLPort();

        try {
            logger.debug("RegisterUser: Sending response");
            JSONObject jsonObj = new JSONObject();
            ObjectNode responseNode = jsonObj.getMapper().createObjectNode();
            responseNode.put("Status", SUCCESS);
            responseNode.put("Port", port);
            jsonObj.getRootNode().set("Response", responseNode);
        } catch (Exception e) {
            logger.warn("Failed to send the output: " + e.getMessage(), e);
        }
    }

    @Override
    protected void renderResult(CMSRequest cmsReq) throws IOException {
        // do nothing, ie, it will not return the default javascript.
    }
}
