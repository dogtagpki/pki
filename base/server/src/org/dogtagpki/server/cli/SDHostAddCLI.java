//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;
import java.util.Enumeration;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPEntry;

/**
 * @author Endi S. Dewata
 */
public class SDHostAddCLI extends CommandCLI {

    public SDHostAddCLI(CLI parent) {
        super("add", "Add security domain host", parent);
    }

    public void createOptions() {
        Option option = new Option(null, "hostname", true, "Hostname");
        option.setArgName("hostname");
        options.addOption(option);

        option = new Option(null, "unsecure-port", true, "Unsecure port (default: 8080)");
        option.setArgName("port");
        options.addOption(option);

        option = new Option(null, "secure-port", true, "Secure port (default: 8443)");
        option.setArgName("port");
        options.addOption(option);

        options.addOption(null, "domain-manager", false, "Domain manager");
        options.addOption(null, "clone", false, "Clone");
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing host ID");
        }

        String hostID = cmdArgs[0];

        String hostname = cmd.getOptionValue("hostname");

        if (hostname == null) {
            throw new Exception("Missing hostname");
        }

        String unsecurePort = cmd.getOptionValue("unsecure-port", "8080");
        String securePort = cmd.getOptionValue("secure-port", "8443");
        boolean domainManager = cmd.hasOption("domain-manager");
        boolean clone = cmd.hasOption("clone");

        String catalinaBase = System.getProperty("catalina.base");
        String serverXml = catalinaBase + "/conf/server.xml";

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadTomcatConfig(serverXml);
        tomcatjss.init();

        String subsystemDir = catalinaBase + File.separator + "ca";
        String subsystemConfDir = subsystemDir + File.separator + "conf";
        String configFile = subsystemConfDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        EngineConfig cs = new EngineConfig(storage);
        cs.load();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);

        LdapAuthInfo authInfo = new LdapAuthInfo();
        authInfo.setPasswordStore(passwordStore);
        authInfo.init(
                authConfig,
                connInfo.getHost(),
                connInfo.getPort(),
                connInfo.getSecure());

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory;
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory = new PKISocketFactory(authInfo.getClientCertNickname());
        } else {
            socketFactory = new PKISocketFactory(connInfo.getSecure());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            String sdDN = "ou=Security Domain," + ldapConfig.getBaseDN();

            String cn = hostname + ":" + securePort;
            String dn = "cn=" + LDAPUtil.escapeRDNValue(cn) + ",cn=CAList," + sdDN;
            logger.info("Adding " + dn);

            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(new LDAPAttribute("objectclass", new String[] { "top", "pkiSubsystem" }));
            attrs.add(new LDAPAttribute("cn", cn));
            attrs.add(new LDAPAttribute("SubsystemName", hostID));
            attrs.add(new LDAPAttribute("Host", hostname));
            attrs.add(new LDAPAttribute("UnSecurePort", unsecurePort));
            attrs.add(new LDAPAttribute("SecurePort", securePort));
            attrs.add(new LDAPAttribute("SecureAgentPort", securePort));
            attrs.add(new LDAPAttribute("SecureAdminPort", securePort));
            attrs.add(new LDAPAttribute("SecureEEClientAuthPort", securePort));
            attrs.add(new LDAPAttribute("DomainManager", domainManager ? "TRUE" : "FALSE"));
            attrs.add(new LDAPAttribute("Clone", clone ? "TRUE" : "FALSE"));

            for (Enumeration<LDAPAttribute> e = attrs.getAttributes(); e.hasMoreElements(); ) {
                LDAPAttribute attr = e.nextElement();
                for (String value : attr.getStringValueArray()) {
                    logger.debug("- " + attr.getName() + ": " + value);
                }
            }

            LDAPEntry entry = new LDAPEntry(dn, attrs);
            conn.add(entry);

        } finally {
            conn.disconnect();
        }
    }
}
