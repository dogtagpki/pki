//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.util.Enumeration;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
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
import netscape.ldap.LDAPEntry;

/**
 */
public class SubsystemACLFindCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemACLFindCLI.class);

    public SubsystemACLFindCLI(CLI parent) {
        super("find", "Find " + parent.parent.getName().toUpperCase() + " ACLs", parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        initializeTomcatJSS();
        String subsystem = parent.parent.getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String instanceId = CMS.getInstanceID();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = CMS.createPasswordStore(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);
        LdapAuthInfo authInfo = getAuthInfo(passwordStore, connInfo, ldapConfig);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(connInfo.getSecure());
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory.setClientCertNickname(authInfo.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig, instanceId);

        try {
            LDAPEntry entry = ldapConfigurator.getEntry("cn=aclResources," + ldapConfig.getBaseDN());

            System.out.println("  dn: " + entry.getDN());

            Enumeration<LDAPAttribute> attrs = entry.getAttributeSet().getAttributes();
            while (attrs.hasMoreElements()) {
                LDAPAttribute attr = attrs.nextElement();
                String name = attr.getName();
                if (name.equalsIgnoreCase("resourceACLS")){
                    Enumeration<String> values = attr.getStringValues();
                    while (values.hasMoreElements()) {
                        String value = values.nextElement();
                        System.out.println("  " + name + ": " + value);
                    }
                }
            }

        } finally {
            conn.disconnect();
        }
    }
}
