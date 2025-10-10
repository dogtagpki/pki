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
package com.netscape.cms.servlet.cert;

import java.io.IOException;
import java.util.Locale;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ArgBlock;

/**
 * Servlet to report the status, ie, the agent-initiated user
 * enrollment is enabled or disabled.
 *
 * @version $Revision$, $Date$
 */
public class DisplayHashUserEnroll extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = -7063912475278810362L;
    private final static String TPL_FILE = "/ra/hashDirUserEnroll.template";
    private final static String TPL_ERROR_FILE = "/ra/GenErrorHashDirEnroll.template";
    private String mFormPath = null;

    public DisplayHashUserEnroll() {
        super();
    }

    /**
     * Initializes the servlet.
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        try {
            mFormPath = sc.getInitParameter(
                        PROP_SUCCESS_TEMPLATE);
            if (mFormPath == null)
                mFormPath = TPL_FILE;
        } catch (Exception e) {
        }

        mTemplates.remove(CMSRequest.SUCCESS);
    }

    @Override
    protected CMSRequest newCMSRequest() {
        return new CMSRequest();
    }

    /**
     * Services the request
     */
    @Override
    protected void process(CMSRequest cmsReq)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();

        AuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "read");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        String reqHost = httpReq.getRemoteHost();

        logger.error(CMS.getLogMessage("ADMIN_SRVLT_ERR_GET_TEMPLATE"));
        cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_NOT_YET_IMPLEMENTED")));
        cmsReq.setStatus(CMSRequest.ERROR);
    }

    private void printError(CMSRequest cmsReq, String errorCode)
            throws EBaseException {
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        HttpServletResponse httpResp = cmsReq.getHttpResp();
        ArgBlock header = new ArgBlock();
        ArgBlock fixed = new ArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        mTemplates.remove(CMSRequest.SUCCESS);
        header.addStringValue("authority", "Registration Manager");
        header.addStringValue("errorCode", errorCode);
        String formPath = TPL_ERROR_FILE;

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(formPath, httpReq, locale);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_ERR_GET_TEMPLATE", formPath, e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(CMSRequest.ERROR);
            return;
        }

        try {
            ServletOutputStream out = httpResp.getOutputStream();

            httpResp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(CMSRequest.SUCCESS);
        } catch (IOException e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_BAD_SERV_OUT_STREAM", "", e.toString()), e);
            cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e));
            cmsReq.setStatus(CMSRequest.ERROR);
        }
    }
}
