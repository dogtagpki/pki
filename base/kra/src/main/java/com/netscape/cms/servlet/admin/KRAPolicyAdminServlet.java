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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;

import org.dogtagpki.legacy.policy.IPolicyProcessor;
import org.dogtagpki.server.kra.KRAEngine;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.kra.KeyRecoveryAuthority;

/**
 * This class is an administration servlet for KRA policy management.
 *
 * KRA is responsible for registering an instance of this with the remote
 * administration subsystem.
 */
@WebServlet(
        name = "krapolicy",
        urlPatterns = "/krapolicy",
        initParams = {
                @WebInitParam(name="ID",        value="krapolicy"),
                @WebInitParam(name="AuthzMgr",  value="BasicAclAuthz"),
                @WebInitParam(name="authority", value="kra")
        }
)
public class KRAPolicyAdminServlet extends PolicyAdminServlet {

    private static final long serialVersionUID = 1L;
    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KRAPolicyAdminServlet.class);

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
     *        The KRAPolicyAdminServlet is ONLY used by the KRA Console
     *        for the following:
     *
     *            SERVLET-NAME           URL-PATTERN
     *            ====================================================
     *            krapolicy              kra/krapolicy
     */
    @Override
    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        logger.debug("KRAPolicyAdminServlet: In Policy Admin Servlet init");

        KRAEngine engine = KRAEngine.getInstance();

        String authority = config.getInitParameter(PROP_AUTHORITY);
        KeyRecoveryAuthority kra = null;

        if (authority != null) {
            kra = (KeyRecoveryAuthority) engine.getSubsystem(authority);
        }

        if (kra == null) {
            throw new ServletException(authority + " does not have policy processor");
        }

        mProcessor = kra.getPolicyProcessor();

        String policyStatus = KeyRecoveryAuthority.ID + ".Policy." + IPolicyProcessor.PROP_ENABLE;

        try {
            if (mConfig.getBoolean(policyStatus, true)) {
                // NOTE:  If "kra.Policy.enable=<boolean>" is missing,
                //        then the referenced instance existed prior
                //        to this name=value pair existing in its
                //        'CS.cfg' file, and thus we err on the
                //        side that the user may still need to
                //        use the policy framework.
                logger.debug("KRAPolicyAdminServlet: Certificate Policy Framework (deprecated) is ENABLED");

            } else {
                // CS 8.1 Default:  kra.Policy.enable=false
                logger.debug("KRAPolicyAdminServlet: Certificate Policy Framework (deprecated) is DISABLED");
            }

        } catch (EBaseException e) {
            throw new ServletException(authority + " does not have a master policy switch called '" + policyStatus + "'");
        }
    }
}
