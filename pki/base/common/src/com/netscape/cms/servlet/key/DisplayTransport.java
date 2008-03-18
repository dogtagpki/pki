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
package com.netscape.cms.servlet.key;


import com.netscape.cms.servlet.base.*;
import com.netscape.cms.servlet.common.*;
import java.io.*;
import java.util.*;
import java.net.*;
import java.util.*;
import java.text.*;
import java.math.*;
import java.security.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.security.x509.*;
import com.netscape.certsrv.common.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.authority.*;
 
import com.netscape.cms.servlet.*;
import com.netscape.certsrv.dbs.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.dbs.keydb.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.kra.*;
import com.netscape.certsrv.security.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.authorization.*;


/**
 * Retrieve Transport Certificate used to 
 * wrap Private key Archival requests
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class DisplayTransport extends CMSServlet {

    private final static String INFO = "displayTransport";

    /**
     * Constructs displayTransport servlet.
     */
    public DisplayTransport() {
        super();
    }

    /**
     * Initializes the servlet.
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mTemplates.remove(CMSRequest.SUCCESS);
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() { 
        return INFO; 
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);

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

        try {
            IKeyRecoveryAuthority kra = 
                (IKeyRecoveryAuthority) mAuthority;
            ITransportKeyUnit tu = kra.getTransportKeyUnit();
            org.mozilla.jss.crypto.X509Certificate transportCert =
                tu.getCertificate();

            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType("text/html");
            String content = ""; 

            content += "<HTML><PRE>";
            String mime64 = 
                "-----BEGIN CERTIFICATE-----\n" + 
                CMS.BtoA(transportCert.getEncoded()) + 
                "-----END CERTIFICATE-----\n";

            content += mime64;
            content += "</PRE></HTML>";
            resp.setContentType("text/html");
            resp.getOutputStream().write(content.getBytes());
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
              CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
        cmsReq.setStatus(CMSRequest.SUCCESS);
    }
}
