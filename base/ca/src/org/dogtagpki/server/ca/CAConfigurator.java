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

import java.net.MalformedURLException;
import java.net.URL;

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

    public void updateSecurityDomainClone() throws Exception {

        CMSEngine engine = CMS.getCMSEngine();

        // cloning a domain master CA, the clone is also master of its domain
        cs.putString("securitydomain.host", engine.getEEHost());
        cs.putString("securitydomain.httpport", engine.getEENonSSLPort());
        cs.putString("securitydomain.httpsadminport", engine.getAdminPort());
        cs.putString("securitydomain.httpsagentport", engine.getAgentPort());
        cs.putString("securitydomain.httpseeport", engine.getEESSLPort());
        cs.putString("securitydomain.select", "new");
    }

    public void disableCRLCachingAndGenerationForClone(String cloneUri) throws MalformedURLException {

        logger.debug("CAInstallerService: disabling CRL caching and generation for clone");

        //Now add some well know entries that we need to disable CRL functionality.
        //With well known values to disable and well known master CRL ID.

        cs.putInteger("ca.certStatusUpdateInterval", 0);
        cs.putBoolean("ca.listenToCloneModifications", false);
        cs.putBoolean("ca.crl.MasterCRL.enableCRLCache", false);
        cs.putBoolean("ca.crl.MasterCRL.enableCRLUpdates", false);

        URL url = new URL(cloneUri);
        String masterHost = url.getHost();
        int masterPort = url.getPort();

        logger.debug("CAInstallerService: master host: " + masterHost);
        logger.debug("CAInstallerService: master port: " + masterPort);

        cs.putString("master.ca.agent.host", masterHost);
        cs.putInteger("master.ca.agent.port", masterPort);
    }

    public void configureStartingCRLNumber(String startingCrlNumber) {
        logger.debug("CAConfigurator: configuring starting CRL number");
        cs.putString("ca.crl.MasterCRL.startingCrlNumber", startingCrlNumber);
    }

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
