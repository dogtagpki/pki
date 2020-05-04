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

import java.security.cert.CertificateException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang.StringUtils;
import org.dogtagpki.cli.CLI;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
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

    public void createOptions() {

        Option action = new Option(null, "action", true, "Desired CA database upgrade action");
        action.setArgName("action");
        options.addOption(action);


        Option issuerDn = new Option(null, "issuer-dn", true, "Optional CA issuer DN");
        issuerDn.setArgName("issuer-dn");
        options.addOption(issuerDn);

        Option vlvFile = new Option(null,"vlv-file",true, "Vlv file to update vlv indexes");
        vlvFile.setArgName("vlv-file");
        options.addOption(vlvFile);

        Option vlvTasksFile = new Option(null,"vlv-tasks-file",true, "Vlv tasks file to update vlv indexes");
        vlvTasksFile.setArgName("vlv-tasks-file");
        options.addOption(vlvTasksFile);

    }

    public void execute(CommandLine cmd) throws Exception {
        this.cmd = cmd;
        super.execute(cmd);
    }

    public void upgrade(String instanceId, LDAPConfig ldapConfig, LdapBoundConnection conn) throws Exception {

        if (cmd.hasOption("action")) {
            String caIssuerDn = null;
            String actionVal = cmd.getOptionValue("action");
            logger.info("Attempting to execute a specific action: " + actionVal);

            if (cmd.hasOption("issuer-dn")) {
                caIssuerDn = cmd.getOptionValue("issuer-dn");
            }

            if ("update-vlv-indexes".equals(actionVal)) {
                updateVlvIndexes(instanceId, caIssuerDn, ldapConfig, conn);
                return;
            } else if ("fix-missing-issuer-names".equals(actionVal)) {
                fixMissingIssuerNames(ldapConfig, conn);
                return;
            } else {
                logger.info("Invalid action requested: " + actionVal);
                return;
            }
        }

        //Take default action which is to upgrade the db with missing issuerNames
        fixMissingIssuerNames(ldapConfig, conn);
    }

    private void fixMissingIssuerNames(LDAPConfig ldapConfig, LdapBoundConnection conn)
            throws EBaseException, LDAPException, CertificateException {

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

    private void updateVlvIndexes(String instanceId, String caIssuerDn, LDAPConfig ldapConfig, LdapBoundConnection conn)
            throws Exception {

        String actionVal = cmd.getOptionValue("action");

        if (StringUtils.isEmpty(actionVal)) {
            logger.info("Invalid number of args for updateVlvIndexes");
            return;
        }

        if (!cmd.hasOption("vlv-file")) {
            logger.info("Command must have a value for argument vlv-file");
            return;
        }

        if (StringUtils.isEmpty(caIssuerDn)) {
            logger.info("Command must have a value for argument issuerDN ");
            return;
        }

        String vlvName = cmd.getOptionValue("vlv-file");
        String vlvTasksName = cmd.getOptionValue("vlv-tasks-file");

        if (StringUtils.isEmpty(vlvName) || StringUtils.isEmpty(vlvTasksName)) {
            logger.info("Command must include vlv-fle and vlv-tasks-file arguments");
            return;
        }

        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, instanceId, caIssuerDn, ldapConfig);

        ldapConfigurator.createAdditionalVLVIndexes("ca", vlvName);
        ldapConfigurator.rebuildAdditionalVLVIndexes("ca", vlvTasksName);

    }

    private CommandLine cmd = null;
}
