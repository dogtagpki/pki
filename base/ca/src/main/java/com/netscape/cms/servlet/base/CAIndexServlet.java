package com.netscape.cms.servlet.base;
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


import java.io.IOException;

import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.common.CMSGateway;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * This is the servlet that builds the index page in
 * various ports.
 */
@WebServlet(
        name = "caindex",
        urlPatterns = "/index",
        initParams = {
                @WebInitParam(name="ID",            value="caindex"),
                @WebInitParam(name="template",      value="index.template"),
                @WebInitParam(name="GetClientCert", value="true"),
                @WebInitParam(name="AuthMgr",       value="certUserDBAuthMgr"),
                @WebInitParam(name="interface",     value="agent")
        }
)
public class CAIndexServlet extends IndexServlet {

    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {

        CMSEngine engine = getCMSEngine();
        CMSGateway gateway = engine.getCMSGateway();

        if (!gateway.getEnableAdminEnroll()) {
            super.process(cmsReq);
            return;
        }

        try {
            cmsReq.getHttpResp().sendRedirect("/ca/adminEnroll.html");
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_FAIL_REDIRECT_ADMIN_ENROLL", e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_REDIRECTING_ADMINENROLL1", e.toString()), e);
        }

        cmsReq.setStatus(CMSRequest.SUCCESS);
    }
}
