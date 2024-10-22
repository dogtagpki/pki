//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.dbs.Repository.IDGenerator;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.request.RequestRepository;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBInitCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBInitCLI.class);

    protected IDGenerator requestIDGenerator;
    protected IDGenerator serialIDGenerator;

    public SubsystemDBInitCLI(CLI parent) {
        super("init", "Initialize " + parent.getParent().getName().toUpperCase() + " database", parent);
    }

    public SubsystemDBInitCLI(String name, String description, CLI parent) {
        super(name, description, parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option("d", true, "NSS database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("f", true, "NSS database password configuration");
        option.setArgName("password config");
        options.addOption(option);

        options.addOption(null, "skip-config", false, "Skip DS server configuration");
        options.addOption(null, "skip-schema", false, "Skip DS schema setup");
        options.addOption(null, "skip-base", false, "Skip base entry setup");
        options.addOption(null, "skip-containers", false, "Skip container entries setup");

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void init(DatabaseConfig dbConfig) throws Exception {

        String value = dbConfig.getString(
                RequestRepository.PROP_REQUEST_ID_GENERATOR,
                RequestRepository.DEFAULT_REQUEST_ID_GENERATOR);
        requestIDGenerator = IDGenerator.fromString(value);
    }

    public void createRangesSubtree(
            LDAPConfig ldapConfig,
            LDAPConfigurator ldapConfigurator) throws Exception {

        if (requestIDGenerator == IDGenerator.LEGACY_2 ||
                serialIDGenerator == IDGenerator.LEGACY_2) {

            // create ou=ranges_v2 for SSNv2
            ldapConfigurator.createEntry(
                    "ou=ranges_v2," + ldapConfig.getBaseDN(),
                    new String[] { "organizationalUnit" });
            return;
        }

        // ou=ranges for SSNv1 is defined in create.ldif so it will
        // be created automatically
    }

    public void createRequestRangesSubtree(
            LDAPConfig ldapConfig,
            DatabaseConfig dbConfig,
            LDAPConfigurator ldapConfigurator) throws Exception {

        String requestRangeRDN = dbConfig.getRequestRangeDN();

        if (StringUtils.isEmpty(requestRangeRDN)) {
            // dbs.requestRangeDN only exists in CA and KRA
            return;
        }

        if (requestIDGenerator == IDGenerator.RANDOM) {
            return;
        }

        // create ou=requests,ou=ranges for SSNv1 or
        // ou=requests,ou=ranges_v2 for SSNv2
        ldapConfigurator.createEntry(
                requestRangeRDN + "," + ldapConfig.getBaseDN(),
                new String[] { "organizationalUnit" });
    }

    public void createSerialRangesSubtree(
            LDAPConfig ldapConfig,
            DatabaseConfig dbConfig,
            LDAPConfigurator ldapConfigurator) throws Exception {

        String serialRangeRDN = dbConfig.getSerialRangeDN();

        if (StringUtils.isEmpty(serialRangeRDN)) {
            // dbs.serialRangeDN only exists in CA and KRA
            return;
        }

        if (serialIDGenerator == IDGenerator.RANDOM) {
            return;
        }

        // create ou=certificateRepository,ou=ranges for SSNv1 or
        // ou=certificateRepository,ou=ranges_v2 for SSNv2
        ldapConfigurator.createEntry(
                serialRangeRDN + "," + ldapConfig.getBaseDN(),
                new String[] { "organizationalUnit" });
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
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig);

        DatabaseConfig dbConfig = cs.getDatabaseConfig();
        init(dbConfig);

        try {
            if (!cmd.hasOption("skip-config")) {
                ldapConfigurator.configureServer();
            }

            if (!cmd.hasOption("skip-schema")) {
                ldapConfigurator.setupSchema();
            }

            if (!cmd.hasOption("skip-base")) {
                ldapConfigurator.createBaseEntry(baseDN);
            }

            if (!cmd.hasOption("skip-containers")) {
                ldapConfigurator.createContainers(subsystem);

                createRangesSubtree(ldapConfig, ldapConfigurator);
                createRequestRangesSubtree(ldapConfig, dbConfig, ldapConfigurator);
                createSerialRangesSubtree(ldapConfig, dbConfig, ldapConfigurator);

                ldapConfigurator.setupACL(subsystem);
            }

        } finally {
            conn.disconnect();
        }
    }
}
