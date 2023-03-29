//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
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
public class SubsystemDBInitCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBInitCLI.class);

    public SubsystemDBInitCLI(CLI parent) {
        super("init", "Initialize " + parent.getParent().getName().toUpperCase() + " database", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option("d", true, "NSS database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("f", true, "NSS database password configuration");
        option.setArgName("password config");
        options.addOption(option);

        options.addOption(null, "setup-schema", false, "Set up schema");
        options.addOption(null, "create-database", false, "Create database");
        options.addOption(null, "create-base", false, "Create base entry");
        options.addOption(null, "create-containers", false, "Create container entries");
        options.addOption(null, "rebuild-indexes", false, "Rebuild indexes");

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

        logger.info("Initializing database " + database + " for " + baseDN);

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        LDAPConnectionConfig connConfig = ldapConfig.getConnectionConfig();

        LdapConnInfo connInfo = new LdapConnInfo(connConfig);
        LdapAuthInfo authInfo = getAuthInfo(passwordStore, connInfo, ldapConfig);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PKISocketFactory socketFactory = new PKISocketFactory(connInfo.getSecure());
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory.setClientCertNickname(authInfo.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnection conn = new LdapBoundConnection(socketFactory, connInfo, authInfo);
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig);

        try {
            ldapConfigurator.initDatabase();

            if (cmd.hasOption("setup-schema")) {
                ldapConfigurator.setupSchema();
            }

            if (cmd.hasOption("create-database")) {
                String databaseDN = "cn=" + LDAPUtil.escapeRDNValue(database) + ",cn=ldbm database, cn=plugins, cn=config";
                ldapConfigurator.createDatabaseEntry(databaseDN, database, baseDN);

                String mappingDN = "cn=\"" + baseDN + "\",cn=mapping tree, cn=config";
                ldapConfigurator.createMappingEntry(mappingDN, database, baseDN);
            }

            if (cmd.hasOption("create-base")) {
                ldapConfigurator.createBaseEntry(baseDN);
            }

            if (cmd.hasOption("create-containers")) {
                ldapConfigurator.createContainers(subsystem);
                ldapConfigurator.setupACL(subsystem);
            }

            ldapConfigurator.createIndexes(subsystem);

            if (cmd.hasOption("rebuild-indexes")) {
                ldapConfigurator.rebuildIndexes(subsystem);
            }

        } finally {
            conn.disconnect();
        }
    }
}
