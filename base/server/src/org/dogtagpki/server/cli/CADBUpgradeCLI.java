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

package org.dogtagpki.server.cli;

import org.dogtagpki.cli.CLI;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv3;

/**
 * @author Endi S. Dewata
 */
public class CADBUpgradeCLI extends SubsystemDBUpgradeCLI {

    public static Logger logger = LoggerFactory.getLogger(CADBUpgradeCLI.class);

    public CADBUpgradeCLI(CLI parent) {
        super("upgrade", "Upgrade CA database", parent);
    }

    public void upgrade(LDAPConfig ldapConfig, LdapBoundConnection conn) throws Exception {

        logger.info("Searching certificates records with missing issuerName");

        String baseDN = ldapConfig.getBaseDN();
        String certRepoDN = "ou=certificateRepository,ou=ca," + baseDN;

        LDAPSearchResults results = conn.search(
                certRepoDN,
                LDAPv3.SCOPE_ONE,
                "(&(objectclass=certificateRecord)(|(!(issuerName=*))(issuerName=)))",
                null,
                false);

        while (results.hasMoreElements()) {

            LDAPEntry entry = results.next();
            logger.info("Updating certificate record " + entry.getDN());

            LDAPAttributeSet attrs = entry.getAttributeSet();

            // get certificate object
            LDAPAttribute userCertificate = attrs.getAttribute("userCertificate;binary");
            byte[] bytes = userCertificate.getByteValues().nextElement();
            X509CertImpl cert = new X509CertImpl(bytes);

            // get issuer DN
            String issuerDN = cert.getIssuerDN().toString();

            logger.info("Setting issuerName to " + issuerDN);
            LDAPModification mods = new LDAPModification(
                    LDAPModification.ADD, new LDAPAttribute("issuerName", issuerDN));
            conn.modify(entry.getDN(), mods);
        }
    }
}
