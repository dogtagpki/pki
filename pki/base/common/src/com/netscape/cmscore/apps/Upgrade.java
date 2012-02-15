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
package com.netscape.cmscore.apps;

import java.io.File;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmsutil.util.Utils;

public final class Upgrade {
    public static void perform422to45(IConfigStore c)
            throws EBaseException {
        jss3(c);
        c.putInteger("agentGateway.https.timeout", 120);
        IConfigStore cs = c.getSubStore("ca");

        if (cs != null && cs.size() > 0) {
            c.putString("ca.publish.mapper.impl.LdapEnhancedMap.class",
                    "com.netscape.certsrv.ldap.LdapEnhancedMap");
        }
        c.putString("cms.version", "4.5");
        c.commit(false);
    }

    public static void perform42to422(IConfigStore c)
            throws EBaseException {
        // upgrade CMS's configuration parameters
        c.putString(
                "eeGateway.dynamicVariables",
                "serverdate=serverdate(),subsystemname=subsystemname(),http=http(),authmgrs=authmgrs(),clacrlurl=clacrlurl()");

        // new OCSP Publisher implemention
        c.putString("ra.publish.publisher.impl.OCSPPublisher.class",
                "com.netscape.certsrv.ldap.OCSPPublisher");
        c.putString("ca.publish.publisher.impl.OCSPPublisher.class",
                "com.netscape.certsrv.ldap.OCSPPublisher");

        // new logging framework
        c.putString("log.impl.file.class",
                "com.netscape.certsrv.logging.RollingLogFile");

        c.putString("log.instance.Audit.bufferSize",
                c.getString("logAudit.bufferSize"));
        c.putString("log.instance.Audit.enable",
                c.getString("logAudit.on"));
        // This feature doesnot work in the previous release
        // But it works now. I don't want people to have their
        // logs auto deleted without notice.It's dangerous.
        c.putString("log.instance.Audit.expirationTime",
                "0"); //Specifically turn it off.
        //			c.getString("logAudit.expirationTime"));
        c.putString("log.instance.Audit.fileName",
                c.getString("logAudit.fileName"));
        c.putString("log.instance.Audit.flushInterval",
                c.getString("logAudit.flushInterval"));
        c.putString("log.instance.Audit.level",
                c.getString("logAudit.level"));
        c.putString("log.instance.Audit.maxFileSize",
                c.getString("logAudit.maxFileSize"));
        c.putString("log.instance.Audit.pluginName",
                "file");
        c.putString("log.instance.Audit.rolloverInterval",
                c.getString("logAudit.rolloverInterval"));
        c.putString("log.instance.Audit.type",
                "audit");

        c.putString("log.instance.Error.bufferSize",
                c.getString("logError.bufferSize"));
        c.putString("log.instance.Error.enable",
                c.getString("logError.on"));
        c.putString("log.instance.Error.expirationTime",
                "0"); //Specifically turn it off.
        //			c.getString("logError.expirationTime"));
        c.putString("log.instance.Error.fileName",
                c.getString("logError.fileName"));
        c.putString("log.instance.Error.flushInterval",
                c.getString("logError.flushInterval"));
        c.putString("log.instance.Error.level",
                c.getString("logError.level"));
        c.putString("log.instance.Error.maxFileSize",
                c.getString("logError.maxFileSize"));
        c.putString("log.instance.Error.pluginName",
                "file");
        c.putString("log.instance.Error.rolloverInterval",
                c.getString("logError.rolloverInterval"));
        c.putString("log.instance.Error.type",
                "system");

        c.putString("log.instance.System.bufferSize",
                c.getString("logSystem.bufferSize"));
        c.putString("log.instance.System.enable",
                c.getString("logSystem.on"));
        c.putString("log.instance.System.expirationTime",
                "0"); //Specifically turn it off.
        //			c.getString("logSystem.expirationTime"));
        c.putString("log.instance.System.fileName",
                c.getString("logSystem.fileName"));
        c.putString("log.instance.System.flushInterval",
                c.getString("logSystem.flushInterval"));
        c.putString("log.instance.System.level",
                c.getString("logSystem.level"));
        c.putString("log.instance.System.maxFileSize",
                c.getString("logSystem.maxFileSize"));
        c.putString("log.instance.System.pluginName",
                "file");
        c.putString("log.instance.System.rolloverInterval",
                c.getString("logSystem.rolloverInterval"));
        c.putString("log.instance.System.type",
                "system");

        if (Utils.isNT()) {
            c.putString("log.impl.NTEventLog.class",
                    "com.netscape.certsrv.logging.NTEventLog");

            c.putString("log.instance.NTAudit.NTEventSourceName",
                    c.getString("logNTAudit.NTEventSourceName"));
            c.putString("log.instance.NTAudit.enable",
                    c.getString("logNTAudit.on"));
            c.putString("log.instance.NTAudit.level",
                    c.getString("logNTAudit.level"));
            c.putString("log.instance.NTAudit.pluginName",
                    "NTEventLog");
            c.putString("log.instance.NTAudit.type",
                    "system");

            c.putString("log.instance.NTSystem.NTEventSourceName",
                    c.getString("logNTSystem.NTEventSourceName"));
            c.putString("log.instance.NTSystem.enable",
                    c.getString("logNTSystem.on"));
            c.putString("log.instance.NTSystem.level",
                    c.getString("logNTSystem.level"));
            c.putString("log.instance.NTSystem.pluginName",
                    "NTEventLog");
            c.putString("log.instance.NTSystem.type",
                    "system");
        }
        c.putString("cms.version", "4.22");
        c.commit(false);
    }

    /**
     * This method handles pre4.2 -> 4.2 configuration
     * upgrade.
     */
    public static void perform(IConfigStore c)
            throws EBaseException {
        boolean isCA = false;
        boolean isRA = false;

        // determine what subsystems do we have?
        IConfigStore cs = c.getSubStore("ca");

        if (cs != null && cs.size() > 0) {
            isCA = true;
        }
        cs = c.getSubStore("ra");
        if (cs != null && cs.size() > 0) {
            isRA = true;
        }

        Setup.installAuthImpls(c);
        Setup.installOIDMap(c);

        // start upgrade processing
        if (isCA) {
            Setup.installPolicyImpls("ca", c);
            Setup.installCACRLExtensions(c);
            Setup.installCAPublishingImpls(c);
            caPublishing(c);
        }

        if (isRA) {
            Setup.installPolicyImpls("ra", c);
        }

        c.putString("eeGateway.dynamicVariables",
                "serverdate=serverdate(),subsystemname=subsystemname(),http=http(),authmgrs=authmgrs()");

        c.putString("cms.version", "4.2");
        // Assumed user backups (including CMS.cfg) the system before
        // upgrading
        c.commit(false);
    }

    /**
     * Upgrade publishing. This function upgrades both enabled
     * or disabled publishing configuration.
     */
    public static void caPublishing(IConfigStore c)
            throws EBaseException {
        c.putString("ca.publish.enable",
                c.getString("ca.enableLdapPublish", "false"));
        c.putString("ca.publish.ldappublish.enable",
                c.getString("ca.enableLdapPublish", "false"));
        c.putString("ca.publish.ldappublish.ldap.ldapauth.authtype",
                c.getString("ca.ldappublish.ldap.ldapauth.authtype", "BasicAuth"));
        c.putString("ca.publish.ldappublish.ldap.ldapauth.bindDN",
                c.getString("ca.ldappublish.ldap.ldapauth.bindDN", ""));
        c.putString("ca.publish.ldappublish.ldap.ldapauth.bindPWPrompt",
                c.getString("ca.ldappublish.ldap.ldapauth.bindPWPrompt", "LDAP Publishing"));
        c.putString("ca.publish.ldappublish.ldap.ldapconn.host",
                c.getString("ca.ldappublish.ldap.ldapconn.host", ""));
        c.putString("ca.publish.ldappublish.ldap.ldapconn.port",
                c.getString("ca.ldappublish.ldap.ldapconn.port", ""));
        c.putString("ca.publish.ldappublish.ldap.ldapconn.secureConn",
                c.getString("ca.ldappublish.ldap.ldapconn.secureConn", "false"));
        c.putString("ca.publish.ldappublish.ldap.ldapconn.version",
                c.getString("ca.ldappublish.ldap.ldapconn.version", "2"));

        // mappers
        c.putString("ca.publish.mapper.instance.LdapCaCertMap.pluginName",
                "LdapDNCompsMap");
        c.putString("ca.publish.mapper.instance.LdapCaCertMap.dnComps",
                c.getString("ca.ldappublish.type.ca.mapper.dnComps"));
        c.putString("ca.publish.mapper.instance.LdapCaCertMap.filterComps",
                c.getString("ca.ldappublish.type.ca.mapper.filterComps"));
        c.putString("ca.publish.mapper.instance.LdapCaCertMap.baseDN",
                c.getString("ca.ldappublish.type.ca.mapper.baseDN"));

        c.putString("ca.publish.mapper.instance.LdapCrlMap.pluginName",
                "LdapDNCompsMap");
        c.putString("ca.publish.mapper.instance.LdapCrlMap.dnComps",
                c.getString("ca.ldappublish.type.crl.mapper.dnComps"));
        c.putString("ca.publish.mapper.instance.LdapCrlMap.filterComps",
                c.getString("ca.ldappublish.type.crl.mapper.filterComps"));
        c.putString("ca.publish.mapper.instance.LdapCrlMap.baseDN",
                c.getString("ca.ldappublish.type.crl.mapper.baseDN"));
        c.putString("ca.publish.mapper.instance.LdapUserCertMap.pluginName",
                "LdapDNCompsMap");
        c.putString("ca.publish.mapper.instance.LdapUserCertMap.dnComps",
                c.getString("ca.ldappublish.type.client.mapper.dnComps"));
        c.putString("ca.publish.mapper.instance.LdapUserCertMap.filterComps",
                c.getString("ca.ldappublish.type.client.mapper.filterComps"));
        c.putString("ca.publish.mapper.instance.LdapUserCertMap.baseDN",
                c.getString("ca.ldappublish.type.client.mapper.baseDN"));

        // publishers
        c.putString("ca.publish.publisher.instance.LdapCaCertPublisher.caCertAttr", "caCertificate;binary");
        c.putString("ca.publish.publisher.instance.LdapCaCertPublisher.caObjectClass", "certificationAuthority");
        c.putString("ca.publish.publisher.instance.LdapCaCertPublisher.pluginName", "LdapCaCertPublisher");
        c.putString("ca.publish.publisher.instance.LdapCrlPublisher.crlAttr", "certificateRevocationList;binary");
        c.putString("ca.publish.publisher.instance.LdapCrlPublisher.pluginName", "LdapCrlPublisher");
        c.putString("ca.publish.publisher.instance.LdapUserCertPublisher.certAttr", "userCertificate;binary");
        c.putString("ca.publish.publisher.instance.LdapUserCertPublisher.pluginName", "LdapUserCertPublisher");

        // rules
        c.putString("ca.publish.rule.instance.LdapCaCertRule.pluginName ",
                "Rule");
        c.putString("ca.publish.rule.instance.LdapCaCertRule.predicate",
                "");
        c.putString("ca.publish.rule.instance.LdapCaCertRule.publisher",
                "LdapCaCertPublisher");
        c.putString("ca.publish.rule.instance.LdapCaCertRule.type",
                "cacert");
        c.putString("ca.publish.rule.instance.LdapCaCertRule.enable",
                "true");
        c.putString("ca.publish.rule.instance.LdapCaCertRule.mapper",
                "LdapCaCertMap");

        c.putString("ca.publish.rule.instance.LdapCrlRule.pluginName",
                "Rule");
        c.putString("ca.publish.rule.instance.LdapCrlRule.predicate", "");
        c.putString("ca.publish.rule.instance.LdapCrlRule.publisher",
                "LdapCrlPublisher");
        c.putString("ca.publish.rule.instance.LdapCrlRule.type", "crl");
        c.putString("ca.publish.rule.instance.LdapCrlRule.enable", "true");
        c.putString("ca.publish.rule.instance.LdapCrlRule.mapper",
                "LdapCrlMap");

        c.putString("ca.publish.rule.instance.LdapUserCertRule.pluginName",
                "Rule");
        c.putString("ca.publish.rule.instance.LdapUserCertRule.predicate", "");
        c.putString("ca.publish.rule.instance.LdapUserCertRule.publisher",
                "LdapUserCertPublisher");
        c.putString("ca.publish.rule.instance.LdapUserCertRule.type", "certs");
        c.putString("ca.publish.rule.instance.LdapUserCertRule.enable", "true");
        c.putString("ca.publish.rule.instance.LdapUserCertRule.mapper",
                "LdapUserCertMap");

        c.removeSubStore("ca.ldappublish");
    }

    /**
     * Upgrade publishing. This function upgrades both enabled
     * or disabled publishing configuration.
     */
    public static void jss3(IConfigStore c)
            throws EBaseException {
        String moddb = c.getString("jss.moddb");

        if (moddb == null)
            return;

        int i = moddb.lastIndexOf("/");
        String dir = moddb.substring(0, i);
        String secmodName = moddb.substring(i + 1);
        String certdb = c.getString("jss.certdb");

        i = certdb.indexOf("/config/cert7.db");
        certdb = certdb.substring(0, i);
        i = certdb.lastIndexOf("/");
        String instID = certdb.substring(i + 1);
        String certPrefix = ".." + File.separator + ".." + File.separator + instID +
                File.separator + "config" + File.separator;
        String keyPrefix = certPrefix;

        c.putString("jss.certPrefix", certPrefix.replace('\\', '/'));
        c.putString("jss.keyPrefix", keyPrefix.replace('\\', '/'));
        c.putString("jss.configDir", dir.replace('\\', '/'));
        c.putString("jss.secmodName", secmodName);

    }
}
