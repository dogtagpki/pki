//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBCreateCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemDBCreateCLI.class);

    public SubsystemDBCreateCLI(CLI parent) {
        super("create", "Create " + parent.getParent().getName().toUpperCase() + " database", parent);
    }

    @Override
    public void createOptions() {
        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        initializeTomcatJSS();
        String subsystem = parent.getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String database = ldapConfig.getDatabase();
        String baseDN = ldapConfig.getBaseDN();

        logger.info("Creating database " + database);

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

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
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig);

        try {
            String databaseDN = "cn=" + LDAPUtil.escapeRDNValue(database) + ",cn=ldbm database,cn=plugins,cn=config";
            ldapConfigurator.createBackendEntry(databaseDN, database, baseDN);

            String mappingDN = "cn=\"" + baseDN + "\",cn=mapping tree,cn=config";
            ldapConfigurator.createMappingEntry(mappingDN, database, baseDN);

        } finally {
            conn.disconnect();
        }
    }
}
