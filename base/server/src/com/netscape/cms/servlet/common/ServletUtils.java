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
package com.netscape.cms.servlet.common;

import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import com.netscape.certsrv.authorization.IAuthzSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;

/**
 * Utility class
 *
 * @version $Revision$, $Date$
 */
public class ServletUtils {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServletUtils.class);

    public final static String AUTHZ_SRC_LDAP = "ldap";
    public final static String AUTHZ_SRC_TYPE = "sourceType";
    public final static String AUTHZ_CONFIG_STORE = "authz";
    public final static String AUTHZ_SRC_XML = "web.xml";
    public final static String PROP_AUTHZ_MGR = "AuthzMgr";
    public final static String PROP_ACL = "ACLinfo";
    public final static String AUTHZ_MGR_BASIC = "BasicAclAuthz";
    public final static String AUTHZ_MGR_LDAP = "DirAclAuthz";

    public static String initializeAuthz(ServletConfig sc,
            IAuthzSubsystem authz, String id) throws ServletException {

        CMSEngine engine = CMS.getCMSEngine();
        String srcType = AUTHZ_SRC_LDAP;

        try {
            IConfigStore authzConfig = engine.getConfigStore().getSubStore(AUTHZ_CONFIG_STORE);
            srcType = authzConfig.getString(AUTHZ_SRC_TYPE, AUTHZ_SRC_LDAP);

        } catch (EBaseException e) {
            logger.warn("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_FAIL_SRC_TYPE"));
        }

        String aclMethod = null;

        if (srcType.equalsIgnoreCase(AUTHZ_SRC_XML)) {

            logger.debug("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_AUTHZ_INITED", ""));
            aclMethod = sc.getInitParameter(PROP_AUTHZ_MGR);

            if (aclMethod != null && aclMethod.equalsIgnoreCase(AUTHZ_MGR_BASIC)) {
                String aclInfo = sc.getInitParameter(PROP_ACL);

                if (aclInfo != null) {
                    try {
                        addACLInfo(authz, aclMethod, aclInfo);
                    } catch (EBaseException ee) {
                        throw new ServletException("Failed to init authz info from xml config file");
                    }

                    logger.debug("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_AUTHZ_MGR_INIT_DONE", id));

                } else {
                    logger.warn("ServletUtils: " + CMS.getLogMessage(
                            "ADMIN_SRVLT_PROP_ACL_NOT_SPEC", PROP_ACL, id,
                            AUTHZ_MGR_LDAP));
                }

            } else {
                logger.warn("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_PROP_ACL_NOT_SPEC",
                        PROP_AUTHZ_MGR, id, AUTHZ_MGR_LDAP));
            }

        } else {
            aclMethod = AUTHZ_MGR_LDAP;
            logger.debug("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_AUTH_LDAP_NOT_XML", id));
        }

        return aclMethod;
    }

    public static void addACLInfo(IAuthzSubsystem authz, String aclMethod,
            String aclInfo) throws EBaseException {

        StringTokenizer tokenizer = new StringTokenizer(aclInfo, "#");

        while (tokenizer.hasMoreTokens()) {
            String acl = tokenizer.nextToken();

            authz.authzMgrAccessInit(aclMethod, acl);
        }
    }

    public static String getACLMethod(String aclInfo, String authzMgr, String id) throws EBaseException {
        CMSEngine engine = CMS.getCMSEngine();
        String srcType = AUTHZ_SRC_LDAP;
        IAuthzSubsystem authz = (IAuthzSubsystem) engine.getSubsystem(IAuthzSubsystem.ID);

        try {
            IConfigStore authzConfig = engine.getConfigStore().getSubStore(AUTHZ_CONFIG_STORE);
            srcType = authzConfig.getString(AUTHZ_SRC_TYPE, AUTHZ_SRC_LDAP);
        } catch (EBaseException e) {
            logger.warn("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_FAIL_SRC_TYPE"));
        }

        String aclMethod = null;

        if (srcType.equalsIgnoreCase(AUTHZ_SRC_XML)) {
            logger.debug("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_AUTHZ_INITED", ""));
            aclMethod = authzMgr;

            if (aclMethod != null && aclMethod.equalsIgnoreCase(AUTHZ_MGR_BASIC)) {
                if (aclInfo != null) {
                    addACLInfo(authz, aclMethod, aclInfo);
                    logger.debug("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_AUTHZ_MGR_INIT_DONE", id));

                } else {
                    logger.warn("ServletUtils: " + CMS.getLogMessage(
                            "ADMIN_SRVLT_PROP_ACL_NOT_SPEC", PROP_ACL, id,
                            AUTHZ_MGR_LDAP));
                }

            } else {
                logger.warn("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_PROP_ACL_NOT_SPEC",
                        PROP_AUTHZ_MGR, id, AUTHZ_MGR_LDAP));
            }

        } else {
            aclMethod = AUTHZ_MGR_LDAP;
            logger.debug("ServletUtils: " + CMS.getLogMessage("ADMIN_SRVLT_AUTH_LDAP_NOT_XML", id));
        }

        return aclMethod;
    }
}
