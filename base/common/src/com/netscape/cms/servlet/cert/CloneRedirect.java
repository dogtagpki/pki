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


import com.netscape.cms.servlet.common.*;
import com.netscape.cms.servlet.base.*;
import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import javax.servlet.*;
import javax.servlet.http.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authority.*;

import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.ca.*;
import com.netscape.certsrv.authentication.*;

import com.netscape.cms.servlet.*;
import com.netscape.certsrv.apps.*;


/**
 * Redirect a request to the Master. This servlet is used in
 * a clone when a requested service (such as CRL) is not available. 
 * It redirects the user to the master.
 *
 * @version $Revision$, $Date$
 */
public class CloneRedirect extends CMSServlet {

    private final static String PROP_REDIRECT_URL = "masterURL";
    private final static String TPL_FILE = "cloneRedirect.template";

    private String mNewUrl = null;
    private String mFormPath = null;

    private ICertificateAuthority mCA = null;

    /**
     * Constructs CloneRedirect servlet.
     */
    public CloneRedirect() {
        super();

    }

    /**
     * Initialize the servlet.
	 * @param sc servlet configuration, read from the web.xml file
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        if (mAuthority instanceof ICertificateAuthority) {
            mCA = (ICertificateAuthority) mAuthority;
            IConfigStore authConfig = mCA.getConfigStore();

            if (authConfig != null) {
                try {
                    mNewUrl = authConfig.getString(PROP_REDIRECT_URL,
                                "*** master URL unavailable, check your configuration ***");
                } catch (EBaseException e) {
                    // do nothing
                }
            }
        }

        if (mAuthority instanceof ICertificateAuthority)
            mCA = (ICertificateAuthority) mAuthority;
		
            // override success to do output with our own template.
        mTemplates.remove(CMSRequest.SUCCESS);
    }

    /**
     * Serves HTTP request.
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        EBaseException error = null;

        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
            throw new ECMSGWException(
                    CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
        }

        CMS.debug("CloneRedirect: " + CMS.getLogMessage("ADMIN_SRVLT_ADD_MASTER_URL", mNewUrl)); 
        header.addStringValue("masterURL", mNewUrl);
        try {
            ServletOutputStream out = resp.getOutputStream();

            if (error == null) {
                String xmlOutput = req.getParameter("xml");
                if (xmlOutput != null && xmlOutput.equals("true")) {
                  outputXML(resp, argSet);
                } else {
                  resp.setContentType("text/html");
                  form.renderOutput(out, argSet);
                  cmsReq.setStatus(CMSRequest.SUCCESS);
                }
            } else {
                cmsReq.setStatus(CMSRequest.ERROR);
                cmsReq.setError(error);
            }
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, 
                CMS.getLogMessage("ADMIN_SRVLT_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(CMS.getLogMessage("CMSGW_ERROR_DISPLAY_TEMPLATE"));
        }
    }

    /**
     * Display information about redirecting to the master's URL info
     */
    private void process(CMSTemplateParams argSet, IArgBlock header,
        HttpServletRequest req,
        HttpServletResponse resp,
        String signatureAlgorithm,
        Locale locale)
        throws EBaseException {

        CMS.debug("CloneRedirect: " + CMS.getLogMessage("ADMIN_SRVLT_ADD_MASTER_URL", mNewUrl)); 
        header.addStringValue("masterURL", mNewUrl);
        return;
    }
}
