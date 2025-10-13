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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cms.servlet.common.IndexTemplateFiller;
import com.netscape.cmscore.apps.CMS;

/**
 * This is the servlet that builds the index page in
 * various ports.
 */
public class IndexServlet extends CMSServlet {

    private static final long serialVersionUID = -8632685610380549L;

    public final static String PROP_TEMPLATE = "template";

    private final static String INFO = "indexServlet";

    private String mTemplateName = null;

    public IndexServlet() {
    }

    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mTemplateName = sc.getInitParameter(PROP_TEMPLATE);

        /*
         mTemplates.put(CMSRequest.SUCCESS,
         new CMSLoadTemplate(
         PROP_SUCCESS_TEMPLATE, PROP_SUCCESS_TEMPLATE_FILLER,
         mTemplateName, new IndexTemplateFiller()));
         */
        mTemplates.remove(CMSRequest.SUCCESS);
    }

    @Override
    public CMSRequest newCMSRequest() {
        return new CMSRequest();
    }

    /**
     * Returns serlvet information.
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP request.
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {

        try {
            renderTemplate(cmsReq, mTemplateName, new IndexTemplateFiller());
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_FAIL_RENDER_TEMPLATE", mTemplateName, e.toString()), e);
            throw new ECMSGWException(CMS.getLogMessage("CMSG_ERROR_DISPLAY_TEMPLATE"), e);
        }

        cmsReq.setStatus(CMSRequest.SUCCESS);
    }
}
