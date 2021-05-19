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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authorization.AuthzToken;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.security.ITransportKeyUnit;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * Retrieve Transport Certificate used to
 * wrap Private key Archival requests
 *
 * @version $Revision$, $Date$
 */
public class DisplayTransport extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -6509083753395783705L;
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
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    /**
     * Returns serlvet information.
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Process the HTTP request.
     *
     * @param cmsReq the object holding the request and response information
     */
    @Override
    public void process(CMSRequest cmsReq) throws EBaseException {

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
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        try {
            KeyRecoveryAuthority kra = (KeyRecoveryAuthority) mAuthority;
            ITransportKeyUnit tu = kra.getTransportKeyUnit();
            org.mozilla.jss.crypto.X509Certificate transportCert =
                    tu.getCertificate();

            resp.setStatus(HttpServletResponse.SC_OK);
            resp.setContentType("text/html");
            String content = "";

            content += "<HTML><PRE>";
            String mime64 = Cert.HEADER + "\n" +
                            Utils.base64encode(transportCert.getEncoded(), true) +
                            Cert.FOOTER + "\n";

            content += mime64;
            content += "</PRE></HTML>";
            resp.setContentType("text/html");
            resp.getOutputStream().write(content.getBytes());
        } catch (Exception e) {
            logger.error(CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()), e);
            throw new ECMSGWException(CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"), e);
        }
        cmsReq.setStatus(ICMSRequest.SUCCESS);
    }
}
