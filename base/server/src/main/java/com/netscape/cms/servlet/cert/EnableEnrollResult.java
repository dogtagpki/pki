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

import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authorization.AuthzToken;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ArgBlock;
import com.netscape.cmscore.security.JssSubsystem;

/**
 * For Face-to-face enrollment, enable EE enrollment feature
 *
 * @version $Revision$, $Date$
 * @see com.netscape.cms.servlet.cert.DisableEnrollResult
 */
public class EnableEnrollResult extends CMSServlet {
    /**
     *
     */
    private static final long serialVersionUID = -2646998784859783012L;
    private final static String TPL_FILE = "enableEnrollResult.template";
    private String mFormPath = null;
    private SecureRandom random = null;

    public EnableEnrollResult() {
        super();
    }

    /**
     * Initializes the servlet.
     */
    @Override
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        // override success to display own output.

        // coming from agent
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;

        mTemplates.remove(CMSRequest.SUCCESS);

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        random = jssSubsystem.getRandomNumberGenerator();
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
                        mAuthzResourceName, "enable");
        } catch (Exception e) {
            // do nothing for now
        }

        if (authzToken == null) {
            cmsReq.setStatus(CMSRequest.UNAUTHORIZED);
            return;
        }

        X509Certificate sslClientCert = null;

        sslClientCert = getSSLClientCertificate(httpReq);
        String dn = sslClientCert.getSubjectDN().toString();

        // Construct an ArgBlock
        ArgBlock args = cmsReq.getHttpParams();

        logger.error(CMS.getLogMessage("CMSGW_CA_FROM_RA_NOT_IMP"));
        cmsReq.setError(new ECMSGWException(CMS.getUserMessage("CMS_GW_NOT_YET_IMPLEMENTED")));
        cmsReq.setStatus(CMSRequest.ERROR);
    }

}
