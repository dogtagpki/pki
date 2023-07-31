//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;
import java.util.Enumeration;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.jss.tomcat.TomcatJSS;

import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.SecurityDomainHost;
import com.netscape.certsrv.system.SecurityDomainSubsystem;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;

/**
 * @author Endi S. Dewata
 */
public class SDSubsystemFindCLI extends CommandCLI {

    public SDSubsystemFindCLI(CLI parent) {
        super("find", "Find security domain subsystems", parent);
    }

    public DomainInfo getDomainInfo(
            LdapBoundConnection conn,
            LDAPConfig ldapConfig) throws Exception {

        String domainDN = "ou=Security Domain," + ldapConfig.getBaseDN();
        LDAPEntry domainEntry = conn.read(domainDN);
        String domainName = domainEntry.getAttribute("name").getStringValues().nextElement();

        DomainInfo domainInfo = new DomainInfo();
        domainInfo.setName(domainName);

        String securityGroupFilter = "(objectclass=pkiSecurityGroup)";
        String subsystemFilter = "(objectclass=pkiSubsystem)";

        LDAPSearchResults subsystemTypeEntries = conn.search(
                domainDN,
                LDAPConnection.SCOPE_ONE,
                securityGroupFilter,
                (String[]) null,
                true,
                (LDAPSearchConstraints) null);

        while (subsystemTypeEntries.hasMoreElements()) {
            // get cn=<subsystem type>List,ou=Security Domain,<base DN>
            String securityGroupDN = subsystemTypeEntries.next().getDN();

            // get <subsystem type>List
            String listName = securityGroupDN.substring(3, securityGroupDN.indexOf(","));

            // get <subsystem type>
            String subsystemType = listName.substring(0, listName.indexOf("List"));

            LDAPSearchResults subsystemEntries = conn.search(
                    securityGroupDN,
                    LDAPConnection.SCOPE_ONE,
                    subsystemFilter,
                    (String[]) null,
                    false,
                    (LDAPSearchConstraints) null);

            while (subsystemEntries.hasMoreElements()) {
                LDAPEntry subsystemEntry = subsystemEntries.next();

                SecurityDomainHost host = new SecurityDomainHost();

                LDAPAttributeSet attrSet = subsystemEntry.getAttributeSet();
                Enumeration<LDAPAttribute> attrs = attrSet.getAttributes();
                while (attrs.hasMoreElements()) {
                    LDAPAttribute attr = attrs.nextElement();
                    String attrName = attr.getName();

                    Enumeration<String> attrValues = attr.getStringValues();
                    while (attrValues.hasMoreElements()) {
                        String attrValue = attrValues.nextElement();

                        if ("Host".equalsIgnoreCase(attrName)) {
                            host.setHostname(attrValue);

                        } else if ("UnSecurePort".equalsIgnoreCase(attrName)) {
                            host.setPort(attrValue);

                        } else if ("SecurePort".equalsIgnoreCase(attrName)) {
                            host.setSecurePort(attrValue);

                        } else if ("SecureEEClientAuthPort".equalsIgnoreCase(attrName)) {
                            host.setSecureEEClientAuthPort(attrValue);

                        } else if ("SecureAgentPort".equalsIgnoreCase(attrName)) {
                            host.setSecureAgentPort(attrValue);

                        } else if ("SecureAdminPort".equalsIgnoreCase(attrName)) {
                            host.setSecureAdminPort(attrValue);

                        } else if ("Clone".equalsIgnoreCase(attrName)) {
                            host.setClone(attrValue);

                        } else if ("SubsystemName".equalsIgnoreCase(attrName)) {
                            host.setSubsystemName(attrValue);

                        } else if ("DomainManager".equalsIgnoreCase(attrName)) {
                            host.setDomainManager(attrValue);
                        }
                    }
                }

                String port = host.getSecurePort();
                if (port == null) port = host.getSecureEEClientAuthPort();
                host.setId(subsystemType + " " + host.getHostname() + " " + port);

                domainInfo.addHost(subsystemType, host);
            }
        }

        return domainInfo;
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String instanceDir = CMS.getInstanceDir();

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.getParent().getParent().getName();
        String subsystemDir = instanceDir + File.separator + subsystem;
        String subsystemConfDir = subsystemDir + File.separator + "conf";
        String configFile = subsystemConfDir + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStorage(configFile);
        EngineConfig cs = new EngineConfig(storage);
        cs.load();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

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

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(connInfo.getSecure());
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory.setClientCertNickname(authInfo.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);

        try {
            DomainInfo domainInfo = getDomainInfo(conn, ldapConfig);
            boolean first = true;

            for (SecurityDomainSubsystem sub : domainInfo.getSubsystems().values()) {
                for (SecurityDomainHost host : sub.getHosts().values()) {

                    if (first) {
                        first = false;
                    } else {
                        System.out.println();
                    }

                    SDSubsystemCLI.printSubsystem(host);
                }
            }

        } finally {
            conn.disconnect();
        }
    }
}
