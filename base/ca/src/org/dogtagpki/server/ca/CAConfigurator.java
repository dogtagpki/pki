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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca;

import org.apache.commons.lang.StringUtils;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

public class CAConfigurator extends Configurator {

    public void deleteSigningRecord(String serialNumber) throws EBaseException, LDAPException {

        if (StringUtils.isEmpty(serialNumber)) {
            throw new PKIException("Missing signing certificate serial number");
        }

        CMSEngine engine = CMS.getCMSEngine();

        LDAPConnection conn = null;
        try {
            IConfigStore dbCfg = cs.getSubStore("internaldb");
            LdapBoundConnFactory dbFactory = new LdapBoundConnFactory("CAInstallerService");
            dbFactory.init(cs, dbCfg, engine.getPasswordStore());

            conn = dbFactory.getConn();

            String basedn = dbCfg.getString("basedn", "");
            String dn = "cn=" + serialNumber + ",ou=certificateRepository,ou=ca," + basedn;

            conn.delete(dn);

        } finally {
            try {
                if (conn != null) conn.disconnect();
            } catch (LDAPException e) {
                logger.warn("Unable to release connection: " + e.getMessage(), e);
            }
        }
    }
}
