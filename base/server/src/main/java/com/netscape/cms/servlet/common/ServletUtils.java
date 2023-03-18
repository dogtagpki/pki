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

import org.dogtagpki.server.authorization.AuthorizationConfig;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.authorization.AuthzSubsystem;

/**
 * Utility class
 *
 * @version $Revision$, $Date$
 */
public class ServletUtils {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ServletUtils.class);

    public final static String AUTHZ_SRC_LDAP = "ldap";
    public final static String AUTHZ_SRC_TYPE = "sourceType";

    public final static String AUTHZ_SRC_XML = "web.xml";
    public final static String PROP_AUTHZ_MGR = "AuthzMgr";
    public final static String PROP_ACL = "ACLinfo";
    public final static String AUTHZ_MGR_BASIC = "BasicAclAuthz";
    public final static String AUTHZ_MGR_LDAP = "DirAclAuthz";

    public static void addACLInfo(AuthzSubsystem authz, String aclMethod,
            String aclInfo) throws EBaseException {

        StringTokenizer tokenizer = new StringTokenizer(aclInfo, "#");

        while (tokenizer.hasMoreTokens()) {
            String acl = tokenizer.nextToken();

            authz.authzMgrAccessInit(aclMethod, acl);
        }
    }
}
