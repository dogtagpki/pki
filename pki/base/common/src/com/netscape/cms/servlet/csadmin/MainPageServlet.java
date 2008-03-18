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


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;
import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.template.ArgList;
import com.netscape.certsrv.template.ArgSet;
import com.netscape.cms.servlet.*;
import com.netscape.certsrv.logging.ILogger;

public class MainPageServlet extends CMSServlet {
    private static final String PROP_AUTHORITY_ID="authorityId";
    private String mAuthorityId = null;
    private String mFormPath = null;

    public MainPageServlet() {
    }

    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mTemplates.remove(CMSRequest.SUCCESS);
        mTemplates.remove(CMSRequest.ERROR);
    }

    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest request = cmsReq.getHttpReq();
        HttpServletResponse response = cmsReq.getHttpResp();

        CMS.debug("MainPageServlet process");
        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;

        try {
            form = getTemplate(mFormPath, request, locale);
        } catch (IOException e) {
            CMS.debug("MainPageServlet process: cant locate the form");
/*
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
*/
        }

        process(argSet, header, ctx, request, response);

        EBaseException error = null;
        try {
            ServletOutputStream out = response.getOutputStream();

            if (error == null) {
                cmsReq.setStatus(CMSRequest.SUCCESS);
                response.setContentType("text/html");
                form.renderOutput(out, argSet);
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("CMSGW_ERR_OUT_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    private void process(CMSTemplateParams argSet, IArgBlock header,
      IArgBlock ctx, HttpServletRequest req, HttpServletResponse resp)
      throws EBaseException {

        int num = 0;        
        IArgBlock rarg = null;
        IConfigStore cs = CMS.getConfigStore();
        int state = 0;
        String host = "";
        String adminInterface = "";
        String eeInterface = "";
        String agentInterface = "";
        try {
            state = cs.getInteger("cs.state", 0);
            host = cs.getString("machineName", "");
            adminInterface = cs.getString("admin.interface.uri", "");
            eeInterface = cs.getString("ee.interface.uri", "");
            agentInterface = cs.getString("agent.interface.uri", "");
        } catch (Exception e) {
        }

        if (state == 0) {
            rarg = CMS.createArgBlock();
            rarg.addStringValue("type", "admin");
            rarg.addStringValue("prefix", "http");
            rarg.addIntegerValue("port", 
              Integer.valueOf(CMS.getEENonSSLPort()).intValue());
            rarg.addStringValue("host", host);
            rarg.addStringValue("uri", adminInterface);
            argSet.addRepeatRecord(rarg);
            num++;
        } else if (state == 1) {
            if (!eeInterface.equals("")) {
                rarg = CMS.createArgBlock();
                rarg.addStringValue("type", "ee");
                rarg.addStringValue("prefix", "https");
                rarg.addIntegerValue("port", 
                  Integer.valueOf(CMS.getEESSLPort()).intValue());
                rarg.addStringValue("host", host);
                rarg.addStringValue("uri", eeInterface);
                argSet.addRepeatRecord(rarg);
                num++;
            }
            if (!agentInterface.equals("")) {
                rarg = CMS.createArgBlock();
                rarg.addStringValue("type", "agent");
                rarg.addStringValue("prefix", "https");
                rarg.addIntegerValue("port", 
                  Integer.valueOf(CMS.getEESSLPort()).intValue());
                rarg.addStringValue("host", host);
                rarg.addStringValue("uri", agentInterface);
                argSet.addRepeatRecord(rarg);
                num++;
            }
        }
        header.addIntegerValue("totalRecordCount", num);
    }
}
