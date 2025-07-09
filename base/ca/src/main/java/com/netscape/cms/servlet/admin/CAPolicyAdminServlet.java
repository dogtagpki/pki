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
package com.netscape.cms.servlet.admin;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;

import org.dogtagpki.legacy.policy.PolicyProcessor;
import org.dogtagpki.server.ca.CAEngine;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;

/**
 * This class is an administration servlet for CA policy management.
 *
 * CA is responsible for registering an instance of this with the remote
 * administration subsystem.
 */
@WebServlet(
        name = "capolicy",
        urlPatterns = "/capolicy",
        initParams = {
                @WebInitParam(name="ID",        value="capolicy"),
                @WebInitParam(name="AuthzMgr",  value="BasicAclAuthz"),
                @WebInitParam(name="authority", value="ca")
        }
)
public class CAPolicyAdminServlet extends PolicyAdminServlet {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAPolicyAdminServlet.class);

    /**
     * CMS 6.1 began utilizing the "Certificate Profiles" framework
     * instead of the legacy "Certificate Policies" framework.
     *
     * Beginning with CS 8.1, to meet the Common Criteria evaluation
     * performed on this version of the product, it was determined
     * that this legacy "Certificate Policies" framework would be
     * deprecated and disabled by default (see Bugzilla Bug #472597).
     *
     * NOTE:  The "Certificate Policies" framework ONLY applied to
     *        to CA, KRA, and legacy RA (pre-CMS 7.0) subsystems.
     *
     *        The CAPolicyAdminServlet is ONLY used by the CA Console
     *        for the following:
     *
     *            SERVLET-NAME           URL-PATTERN
     *            ====================================================
     *            capolicy               ca/capolicy
     */
    @Override
    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        logger.debug("CAPolicyAdminServlet: In Policy Admin Servlet init");

        CAEngine engine = CAEngine.getInstance();

        String authority = config.getInitParameter(PROP_AUTHORITY);
        CertificateAuthority ca = null;

        if (authority != null) {
            ca = engine.getCA();
        }

        if (ca == null) {
            throw new ServletException(authority + " does not have policy processor");
        }

        mProcessor = engine.getCAPolicy().getPolicyProcessor();

        String policyStatus = CertificateAuthority.ID + ".Policy." + PolicyProcessor.PROP_ENABLE;

        try {
            if (mConfig.getBoolean(policyStatus, true)) {
                // NOTE:  If "ca.Policy.enable=<boolean>" is missing,
                //        then the referenced instance existed prior
                //        to this name=value pair existing in its
                //        'CS.cfg' file, and thus we err on the
                //        side that the user may still need to
                //        use the policy framework.
                logger.debug("CAPolicyAdminServlet: Certificate Policy Framework (deprecated) is ENABLED");

            } else {
                // CS 8.1 Default:  ca.Policy.enable=false
                logger.debug("CAPolicyAdminServlet: Certificate Policy Framework (deprecated) is DISABLED");
            }

        } catch (EBaseException e) {
            throw new ServletException(authority + " does not have a master policy switch called '" + policyStatus + "'");
        }
    }
}
