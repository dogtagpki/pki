package com.netscape.pkisilent.common;

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

import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * CMS Test framework .
 * This class reads,modifies and saves CS.cfg file
 */

public class CMSConfig extends ServerInfo {

    /**
     * Constructor . Reads the CS.cfg file .Takes the parameter for Configfile ( Provide fullpath)
     */

    public CMSConfig(String confFile) {
        CMSConfigFile = confFile;
        System.out.println(CMSConfigFile);
        readCMSConfig();
    }

    private void readCMSConfig() {

        try {
            FileInputStream fiscfg = new FileInputStream(CMSConfigFile);

            CMSprops = new CMSProperties();
            CMSprops.load(fiscfg);
            System.out.println("Reading CMS Config file successful");
            fiscfg.close();
            System.out.println("Number in size " + CMSprops.size());
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
        }

    }

    /**
     * Saves the config file
     **/

    public void saveCMSConfig() {
        try {
            // Properties s = new Properties(CMSprops);
            FileOutputStream fos = new FileOutputStream(CMSConfigFile);

            System.out.println("Number in size " + CMSprops.size());
            // CMSprops.list(System.out);
            CMSprops.store(fos, null);
            System.out.println("Writing to CMS Config file successful");
            fos.close();
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
        }

    }

    // AdminEnrollment

    public void EnableAdminEnrollment() {
        CMSprops.setProperty("cmsgateway.enableAdminEnroll", "true");

    }

    // Authentication   

    // Enable DirectoryBased Authentication
    /**
     * Takes parameters : secureConnection( true/false), basedn, ldaphostname, lapdaportnumber ( in case of secured connection give ldap secured port)
     */

    public void EnableDirEnrollment(boolean secureConn, String ldapbase, String lhost, String lport) {
        CMSprops.setProperty("auths.instance.UserDirEnrollment.dnpattern",
                "UID=$attr.uid,E=$attr.mail.1,CN=$attr.cn,OU=$dn.ou.2,O=$dn.o,C=US");
        CMSprops.setProperty("auths.instance.UserDirEnrollment.ldap.basedn",
                ldapbase);
        CMSprops.setProperty(
                "auths.instance.UserDirEnrollment.ldap.ldapconn.host", lhost);
        CMSprops.setProperty(
                "auths.instance.UserDirEnrollment.ldap.ldapconn.version", "3");
        CMSprops.setProperty("auths.instance.UserDirEnrollment.ldap.maxConns",
                "8");
        CMSprops.setProperty("auths.instance.UserDirEnrollment.ldap.minConns",
                "2");
        // CMSprops.setProperty("auths.instance.UserDirEnrollment.ldapByteAttributes=","");
        CMSprops.setProperty(
                "auths.instance.UserDirEnrollment.ldapStringAttributes", "mail");
        CMSprops.setProperty("auths.instance.UserDirEnrollment.pluginName",
                "UidPwdDirAuth");
        if (secureConn) {
            CMSprops.setProperty(
                    "auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn",
                    "true");
            CMSprops.setProperty(
                    "auths.instance.UserDirEnrollment.ldap.ldapconn.port", lport);

        } else {
            CMSprops.setProperty(
                    "auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn",
                    "false");
            CMSprops.setProperty(
                    "auths.instance.UserDirEnrollment.ldap.ldapconn.port", lport);

        }
    }

    public void DisableDirEnrollment() {
        CMSprops.remove("auths.instance.UserDirEnrollment.dnpattern");
        CMSprops.remove("auths.instance.UserDirEnrollment.ldap.basedn");
        CMSprops.remove("auths.instance.UserDirEnrollment.ldap.ldapconn.host");
        CMSprops.remove("auths.instance.UserDirEnrollment.ldap.ldapconn.port");
        CMSprops.remove(
                "auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn");
        CMSprops.remove("auths.instance.UserDirEnrollment.ldap.ldapconn.version");
        CMSprops.remove("auths.instance.UserDirEnrollment.ldap.maxConns");
        CMSprops.remove("auths.instance.UserDirEnrollment.ldap.minConns");
        CMSprops.remove("auths.instance.UserDirEnrollment.ldapByteAttributes=");
        CMSprops.remove("auths.instance.UserDirEnrollment.ldapStringAttributes");
        CMSprops.remove("auths.instance.UserDirEnrollment.pluginName");

    }

    public void EnableCMCAuth() {

        CMSprops.setProperty("auths.instance.testcmc.pluginName",
                "CMCAuthentication");
    }

    /**
     * Takes parameters : secureConnection( true/false), ldapbinddn, ldapbindnpassword,ldaphostname, lapdaportnumber ( in case of secured connection give ldap secured port), basedn (e.g ou=people,o=mcom.com)
     */

    void EnablePortalAuth(boolean secureConn, String ldaprootDN, String ldaprootDNPW, String lhost, String lport,
            String lbsuffix) {
        String certnickname = null;

        CMSprops.setProperty("auths.instance.PortalEnrollment.pluginName",
                "PortalEnroll");
        CMSprops.setProperty("auths.instance.PortalEnrollment.dnpattern",
                "uid=$attr.uid,cn=$attr.cn,O=$dn.co,C=$dn.c");
        CMSprops.setProperty("auths.instance.PortalEnrollment.ldap.basedn",
                lbsuffix);
        CMSprops.setProperty("auths.instance.PortalEnrollment.ldap.maxConns",
                "3");
        CMSprops.setProperty("auths.instance.PortalEnrollment.ldap.minConns",
                "2");
        CMSprops.setProperty("auths.instance.PortalEnrollment.ldap.objectclass",
                "inetOrgPerson");
        CMSprops.setProperty(
                "auths.instance.PortalEnrollment.ldap.ldapauth.bindDN",
                ldaprootDN);
        CMSprops.setProperty(
                "auths.instance.PortalEnrollment.ldap.ldapauth.bindPassword",
                ldaprootDNPW);
        CMSprops.setProperty(
                "auths.instance.PortalEnrollment.ldap.ldapauth.bindPWPrompt",
                "Rule PortalEnrollment");
        CMSprops.setProperty(
                "auths.instance.PortalEnrollment.ldap.ldapconn.host", lhost);
        if (secureConn) {
            CMSprops.setProperty(
                    "auths.instance.PortalEnrollment.ldap.ldapconn.secureConn",
                    "true");
            CMSprops.setProperty(
                    "auths.instance.PortalEnrollment.ldap.ldapauth.clientCertNickname",
                    certnickname);
            CMSprops.setProperty(
                    "auths.instance.PortalEnrollment.ldap.ldapauth.authtype",
                    "SslClientAuth");
            CMSprops.setProperty(
                    "auths.instance.PortalEnrollment.ldap.ldapconn.port", lport);

        } else {
            CMSprops.setProperty(
                    "auths.instance.PortalEnrollment.ldap.ldapconn.secureConn",
                    "false");
            CMSprops.setProperty(
                    "auths.instance.PortalEnrollment.ldap.ldapconn.port", lport);
            CMSprops.setProperty(
                    "auths.instance.PortalEnrollment.ldap.ldapauth.authtype",
                    "BasicAuth");
        }

        CMSprops.setProperty(
                "auths.instance.PortalEnrollment.ldap.ldapconn.version", "3");

    }

    // Publishing 
    /**
     * Takes parameters : secureConnection( true/false), ldapbinddn, ldapbindnpassword,ldaphostname, lapdaportnumber ( in case of secured connection give ldap secured port)
     */

    public void EnablePublishing(boolean secureConn, String ldaprootDN, String ldaprootDNPW, String lhost, String lport) {

        CMSprops.setProperty("ca.publish.enable", "true");
        CMSprops.setProperty("ca.publish.ldappublish.enable", "true");
        if (secureConn) {
            CMSprops.setProperty(
                    "ca.publish.ldappublish.ldap.ldapconn.secureConn", "true");
            CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapconn.port",
                    lport);

            CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.authtype",
                    "SslClientAuth");
        } else {
            CMSprops.setProperty(
                    "ca.publish.ldappublish.ldap.ldapconn.secureConn", "false");
            CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapconn.port",
                    lport);
            CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.authtype",
                    "BasicAuth");
        }

        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.bindDN",
                ldaprootDN);
        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.bindPassword",
                ldaprootDNPW);
        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.bindPWPrompt",
                "CA LDAP Publishing");

        // set the hostname with fully qulified name if you are using SSL
        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapconn.host", lhost);
        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapconn.version", "3");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapCaSimpleMap.class",
                "com.netscape.cms.publish.mappers.LdapCaSimpleMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapDNCompsMap.class",
                "com.netscape.cms.publish.mappers.Lda pCertCompsMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapDNExactMap.class",
                "com.netscape.cms.publish.mappers.LdapCertExactMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapEnhancedMap.class",
                "com.netscape.cms.publish.mappers.LdapEnhancedMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapSimpleMap.class",
                "com.netscape.cms.publish.mappers.LdapSimpleMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapSubjAttrMap.class",
                "com.netscape.cms.publish.mappers.LdapCertSubjMap");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapCaCertMap.createCAEntry", "true");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapCaCertMap.dnPattern",
                "UID=CManager,OU=people,O=mcom.com");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapCaCertMap.pluginName",
                "LdapCaSimpleMap");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapCrlMap.createCAEntry", "true");
        CMSprops.setProperty("ca.publish.mapper.instance.LdapCrlMap.dnPattern",
                "UID=CManager,OU=people,O=mcom.com");
        CMSprops.setProperty("ca.publish.mapper.instance.LdapCrlMap.pluginName",
                "LdapCaSimpleMap");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapUserCertMap.dnPattern",
                "UID=$subj.UID,OU=people,O=mcom.com");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapUserCertMap.pluginName",
                "LdapSimpleMap");
        CMSprops.setProperty(
                "ca.publish.publisher.impl.FileBasedPublisher.class",
                "com.netscape.cms.publish.publishers.FileBasedPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.impl.LdapCaCertPublisher.class",
                "com.netscape.cms.publish.publishers.LdapCaCertPublisher");
        CMSprops.setProperty("ca.publish.publisher.impl.LdapCrlPublisher.class",
                "com.netscape.cms.publish.publishers.LdapCrlPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.impl.LdapUserCertPublisher.class",
                "com.netscape.cms.publish.publishers.LdapUserCertPublisher");
        CMSprops.setProperty("ca.publish.publisher.impl.OCSPPublisher.class",
                "com.netscape.cms.publish.publishers.OCSPPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCaCertPublisher.caCertAttr",
                "caCertificate;binary");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCaCertPublisher.caObjectClass",
                "certificationAuthority");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCaCertPublisher.pluginName",
                "LdapCaCertPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCrlPublisher.crlAttr",
                "certificateRevocationList;binary");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCrlPublisher.pluginName",
                "LdapCrlPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapUserCertPublisher.certAttr",
                "userCertificate;binary");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapUserCertPublisher.pluginName",
                "LdapUserCertPublisher");
    }

    public void DisablePublishing(boolean secureConn, String ldaprootDN, String ldaprootDNPW, String lhost,
            String lport, String base) {

        CMSprops.setProperty("ca.publish.enable", "false");
        CMSprops.setProperty("ca.publish.ldappublish.enable", "false");
        if (secureConn) {
            CMSprops.setProperty(
                    "ca.publish.ldappublish.ldap.ldapconn.secureConn", "false");
            CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapconn.port",
                    lport);

            CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.authtype",
                    "SslClientAuth");
        } else {
            CMSprops.setProperty(
                    "ca.publish.ldappublish.ldap.ldapconn.secureConn", "false");
            CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapconn.port",
                    lport);
            CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.authtype",
                    "BasicAuth");
        }

        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.bindDN",
                ldaprootDN);
        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.bindPassword",
                ldaprootDNPW);
        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapauth.bindPWPrompt",
                "CA LDAP Publishing");

        // set the hostname with fully qulified name if you are using SSL
        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapconn.host", lhost);
        CMSprops.setProperty("ca.publish.ldappublish.ldap.ldapconn.version", "3");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapCaSimpleMap.class",
                "com.netscape.cms.publish.mappers.LdapCaSimpleMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapDNCompsMap.class",
                "com.netscape.cms.publish.mappers.Lda pCertCompsMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapDNExactMap.class",
                "com.netscape.cms.publish.mappers.LdapCertExactMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapEnhancedMap.class",
                "com.netscape.cms.publish.mappers.LdapEnhancedMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapSimpleMap.class",
                "com.netscape.cms.publish.mappers.LdapSimpleMap");
        CMSprops.setProperty("ca.publish.mapper.impl.LdapSubjAttrMap.class",
                "com.netscape.cms.publish.mappers.LdapCertSubjMap");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapCaCertMap.createCAEntry",
                "false");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapCaCertMap.dnPattern",
                "UID=CManager,OU=people," + base);
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapCaCertMap.pluginName",
                "LdapCaSimpleMap");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapCrlMap.createCAEntry", "false");
        CMSprops.setProperty("ca.publish.mapper.instance.LdapCrlMap.dnPattern",
                "UID=CManager,OU=people," + base);
        CMSprops.setProperty("ca.publish.mapper.instance.LdapCrlMap.pluginName",
                "LdapCaSimpleMap");
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapUserCertMap.dnPattern",
                "UID=$subj.UID,OU=people," + base);
        CMSprops.setProperty(
                "ca.publish.mapper.instance.LdapUserCertMap.pluginName",
                "LdapSimpleMap");
        CMSprops.setProperty(
                "ca.publish.publisher.impl.FileBasedPublisher.class",
                "com.netscape.cms.publish.publishers.FileBasedPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.impl.LdapCaCertPublisher.class",
                "com.netscape.cms.publish.publishers.LdapCaCertPublisher");
        CMSprops.setProperty("ca.publish.publisher.impl.LdapCrlPublisher.class",
                "com.netscape.cms.publish.publishers.LdapCrlPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.impl.LdapUserCertPublisher.class",
                "com.netscape.cms.publish.publishers.LdapUserCertPublisher");
        CMSprops.setProperty("ca.publish.publisher.impl.OCSPPublisher.class",
                "com.netscape.cms.publish.publishers.OCSPPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCaCertPublisher.caCertAttr",
                "caCertificate;binary");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCaCertPublisher.caObjectClass",
                "certificationAuthority");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCaCertPublisher.pluginName",
                "LdapCaCertPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCrlPublisher.crlAttr",
                "certificateRevocationList;binary");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapCrlPublisher.pluginName",
                "LdapCrlPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapUserCertPublisher.certAttr",
                "userCertificate;binary");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.LdapUserCertPublisher.pluginName",
                "LdapUserCertPublisher");
    }

    public void CreateOCSPPublisher(String OCSPHost, String OCSPPort, String OCSPEEPort) {
        // Set host nmae with fully qualified hostname 
        String location = "http://" + OCSPHost + ":" + OCSPEEPort + "/ocsp";

        CMSprops.setProperty("ca.crl.MasterCRL.alwaysUpdate", "true");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.CAOCSPPublisher.host", OCSPHost);
        CMSprops.setProperty(
                "ca.publish.publisher.instance.CAOCSPPublisher.path",
                "/ocsp/addCRL");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.CAOCSPPublisher.pluginName",
                "OCSPPublisher");
        CMSprops.setProperty(
                "ca.publish.publisher.instance.CAOCSPPublisher.port", OCSPPort);
        CMSprops.setProperty(
                "ca.publish.rule.instance.OCSPPublishingRule.enable", "true");
        CMSprops.setProperty(
                "ca.publish.rule.instance.OCSPPublishingRule.mapper", "");
        CMSprops.setProperty(
                "ca.publish.rule.instance.OCSPPublishingRule.pluginName", "Rule");
        CMSprops.setProperty(
                "ca.publish.rule.instance.OCSPPublishingRule.predicate", "");
        CMSprops.setProperty(
                "ca.publish.rule.instance.OCSPPublishingRule.publisher",
                "CAOCSPPublisher");
        CMSprops.setProperty("ca.publish.rule.instance.OCSPPublishingRule.type",
                "crl");
        CMSprops.setProperty("ca.Policy.rule.AuthInfoAccessExt.ad0_location",
                location);
        CMSprops.setProperty(
                "ca.Policy.rule.AuthInfoAccessExt.ad0_location_type", "URL");
        CMSprops.setProperty("ca.Policy.rule.AuthInfoAccessExt.ad0_method",
                "ocsp");
        CMSprops.setProperty("ca.Policy.rule.AuthInfoAccessExt.critical",
                "false");
        CMSprops.setProperty("ca.Policy.rule.AuthInfoAccessExt.enable", "true");
        CMSprops.setProperty("ca.Policy.rule.AuthInfoAccessExt.implName",
                "AuthInfoAccessExt");
        CMSprops.setProperty("ca.Policy.rule.AuthInfoAccessExt.numADs", "1");
        CMSprops.setProperty("ca.Policy.rule.AuthInfoAccessExt.predicate",
                "HTTP_PARAMS.certType == client");

    }

    public void EnableOCSPLDAPStore(String certInstanceID) {
        String certNickName = "ocspSigningCert cert-" + certInstanceID;

        CMSprops.setProperty("ocsp.storeId", "ldapStore");
        CMSprops.setProperty("ocsp.store.defStore.byName", "true");
        CMSprops.setProperty("ocsp.store.defStore.class",
                "com.netscape.cms.ocsp.DefStore");
        CMSprops.setProperty("ocsp.store.defStore.includeNextUpdate", "true");
        CMSprops.setProperty("ocsp.store.defStore.notFoundAsGood", "true");
        CMSprops.setProperty("ocsp.store.ldapStore.baseDN0", ldapBaseSuffix);
        CMSprops.setProperty("ocsp.store.ldapStore.byName", "true");
        CMSprops.setProperty("ocsp.store.ldapStore.caCertAttr",
                "cACertificate;binary");
        CMSprops.setProperty("ocsp.store.ldapStore.class",
                "com.netscape.cms.ocsp.LDAPStore");
        CMSprops.setProperty("ocsp.store.ldapStore.crlAttr",
                "certificateRevocationList;binary");
        CMSprops.setProperty("ocsp.store.ldapStore.host0", ldapHost);
        CMSprops.setProperty("ocsp.store.ldapStore.includeNextUpdate", "true");
        CMSprops.setProperty("ocsp.store.ldapStore.notFoundAsGood", "true");
        CMSprops.setProperty("ocsp.store.ldapStore.numConns", "1");
        CMSprops.setProperty("ocsp.store.ldapStore.port0", ldapPort);
        CMSprops.setProperty("ocsp.store.ldapStore.refreshInSec0", "864");
        CMSprops.setProperty("ocsp.signing.certnickname", certNickName);
        CMSprops.setProperty("ocsp.signing.defaultSigningAlgorithm",
                "MD5withRSA");
        CMSprops.setProperty("ocsp.signing.tokenname", "internal");

    }

    public void SetupKRAConnectorInCA(String certInstanceID, String KRAHost, String KRAPort) {
        String certNickName = "Server-Cert " + certInstanceID;

        CMSprops.setProperty("ca.connector.KRA.enable", "true");
        CMSprops.setProperty("ca.connector.KRA.host", KRAHost);
        CMSprops.setProperty("ca.connector.KRA.local", "false");
        CMSprops.setProperty("ca.connector.KRA.nickName", certNickName);
        CMSprops.setProperty("ca.connector.KRA.port", KRAPort);
        CMSprops.setProperty("ca.connector.KRA.timeout", "30");
        CMSprops.setProperty("ca.connector.KRA.uri", "/kra/connector");

    }

    public void DisableCardCryptoValidationinTKS() {
        CMSprops.setProperty("cardcryptogram.validate.enable", "false");
    }

    // Policies 
    public void DefaultValidityRule(String SubsystemType, String lagtime, String leadtime, String maxValidity) {
        if (SubsystemType.equals("ca")) {
            CMSprops.setProperty("ca.Policy.rule.DefaultValidityRule.enable",
                    "true");
            CMSprops.setProperty("ca.Policy.rule.DefaultValidityRule.implName",
                    "ValidityConstraints");
            CMSprops.setProperty("ca.Policy.rule.DefaultValidityRule.lagTime",
                    lagtime);
            CMSprops.setProperty("ca.Policy.rule.DefaultValidityRule.leadTime",
                    leadtime);
            CMSprops.setProperty(
                    "ca.Policy.rule.DefaultValidityRule.maxValidity",
                    maxValidity);
            CMSprops.setProperty(
                    "ca.Policy.rule.DefaultValidityRule.minValidity", "1");
            CMSprops.setProperty(
                    "ca.Policy.rule.DefaultValidityRule.notBeforeSkew", "5");
            CMSprops.setProperty("ca.Policy.rule.DefaultValidityRule.predicate",
                    null);
        } else {

            CMSprops.setProperty("ra.Policy.rule.DefaultValidityRule.enable",
                    "true");
            CMSprops.setProperty("ra.Policy.rule.DefaultValidityRule.implName",
                    "ValidityConstraints");
            CMSprops.setProperty("ra.Policy.rule.DefaultValidityRule.lagTime",
                    lagtime);
            CMSprops.setProperty("ra.Policy.rule.DefaultValidityRule.leadTime",
                    leadtime);
            CMSprops.setProperty(
                    "ra.Policy.rule.DefaultValidityRule.maxValidity",
                    maxValidity);
            CMSprops.setProperty(
                    "ra.Policy.rule.DefaultValidityRule.minValidity", "1");
            CMSprops.setProperty(
                    "ra.Policy.rule.DefaultValidityRule.notBeforeSkew", "5");
            CMSprops.setProperty("ra.Policy.rule.DefaultValidityRule.predicate",
                    null);
        }

    }

    // Main Function
    public static void main(String args[]) {
        System.out.println(args.length);

        if (args.length < 1) {
            System.out.println("Usage : ConfigFilePath");
            System.exit(-1);
        }

        CMSConfig s = new CMSConfig(args[0]);
        boolean secureC = false;

        // s.EnableDirEnrollment(secureC);	
        s.saveCMSConfig();

    }// end of function main

} // end of class 

