//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.base.PropConfigStore;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

import netscape.ldap.LDAPConnection;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBInitCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBInitCLI.class);

    public SubsystemDBInitCLI(CLI parent) {
        super("init", "Initialize " + parent.getParent().getName().toUpperCase() + " database", parent);
    }

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
        options.addOption(null, "setup-replication", false, "Set up replication");
        options.addOption(null, "replication-security", true, "Replication security");
        options.addOption(null, "replication-port", true, "Replication port");
        options.addOption(null, "master-replication-port", true, "Master replication port");
        options.addOption(null, "setup-db-manager", false, "Set up database manager");
        options.addOption(null, "setup-vlv-indexes", false, "Set up VLV indexes");

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(CommandLine cmd) throws Exception {

        String catalinaBase = System.getProperty("catalina.base");

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
        tomcatjss.init();

        String subsystem = parent.getParent().getName();
        String configFile = catalinaBase + File.separator + subsystem + File.separator +
                "conf" + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        EngineConfig cs = new EngineConfig(storage);
        cs.load();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        String database = ldapConfig.getDatabase();
        String baseDN = ldapConfig.getBaseDN();

        logger.info("Initializing database " + database + " for " + baseDN);

        String instanceId = cs.getInstanceID();

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
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig, instanceId);

        try {
            ldapConfigurator.configureDirectory();
            ldapConfigurator.enableUSN();

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

            if (cmd.hasOption("setup-replication")) {
                String replicationSecurity = cmd.getOptionValue("replication-security");
                String replicationPort = cmd.getOptionValue("replication-port");
                String masterReplicationPort = cmd.getOptionValue("master-replication-port");

                setupReplication(
                        cs,
                        passwordStore,
                        replicationSecurity,
                        replicationPort,
                        masterReplicationPort);
            }

            if (cmd.hasOption("setup-db-manager")) {
                ldapConfigurator.setupDatabaseManager();
            }

            if (cmd.hasOption("setup-vlv-indexes")) {
                ldapConfigurator.createVLVIndexes(subsystem);
                ldapConfigurator.rebuildVLVIndexes(subsystem);
            }

            cs.commit(false);

        } finally {
            conn.disconnect();
        }
    }

    public void setupReplication(
            EngineConfig cs,
            IPasswordStore passwordStore,
            String replicationSecurity,
            String replicaReplicationPort,
            String masterReplicationPort) throws Exception {

        String hostname = cs.getHostname();
        String instanceId = cs.getInstanceID();
        String subsystem = cs.getType().toLowerCase();
        PreOpConfig preopConfig = cs.getPreOpConfig();

        PKISocketConfig socketConfig = cs.getSocketConfig();

        LDAPConfig ldapConfig = cs.getInternalDBConfig();
        LDAPConnectionConfig replicaConnConfig = ldapConfig.getConnectionConfig();
        String replicaHostname = replicaConnConfig.getString("host", "");
        String replicaPort = replicaConnConfig.getString("port", "");

        if (replicaReplicationPort == null || replicaReplicationPort.equals("")) {
            replicaReplicationPort = replicaPort;
        }

        LdapBoundConnFactory ldapFactory = new LdapBoundConnFactory("LDAPConfigurator");
        ldapFactory.init(socketConfig, ldapConfig, passwordStore);

        LDAPConnection conn = ldapFactory.getConn();
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig, instanceId);

        try {
            LDAPConfig masterConfig = preopConfig.getSubStore("internaldb.master", LDAPConfig.class);
            LDAPConnectionConfig masterConnConfig = masterConfig.getConnectionConfig();
            String masterHostname = masterConnConfig.getString("host", "");
            String masterPort = masterConnConfig.getString("port", "");

            if (masterReplicationPort == null || masterReplicationPort.equals("")) {
                masterReplicationPort = masterPort;
            }

            String masterReplicationPassword = preopConfig.getString("internaldb.master.replication.password", "");
            String replicaReplicationPassword = passwordStore.getPassword("replicationdb", 0);

            // set master ldap password (if it exists) temporarily in password store
            // in case it is needed for replication.  Not stored in password.conf.

            LDAPAuthenticationConfig masterAuthConfig = masterConfig.getAuthenticationConfig();
            String masterPassword = masterAuthConfig.getString("password", "");

            if (!masterPassword.equals("")) {
                masterAuthConfig.putString("bindPWPrompt", "master_internaldb");
                passwordStore.putPassword("master_internaldb", masterPassword);
                passwordStore.commit();
            }

            LdapBoundConnFactory masterFactory = new LdapBoundConnFactory("MasterLDAPConfigurator");
            masterFactory.init(socketConfig, masterConfig, passwordStore);

            LDAPConnection masterConn = masterFactory.getConn();
            LDAPConfigurator masterConfigurator = new LDAPConfigurator(masterConn, masterConfig);

            try {
                String masterAgreementName = "masterAgreement1-" + hostname + "-" + instanceId;
                String replicaAgreementName = "cloneAgreement1-" + hostname + "-" + instanceId;

                DatabaseConfig dbConfig = cs.getDatabaseConfig();
                int beginReplicaNumber = dbConfig.getInteger("beginReplicaNumber", 1);
                int endReplicaNumber = dbConfig.getInteger("endReplicaNumber", 100);
                logger.info("Current replica number range: " + beginReplicaNumber + "-" + endReplicaNumber);

                beginReplicaNumber = setupReplicationAgreements(
                        masterConfigurator,
                        ldapConfigurator,
                        masterAgreementName,
                        replicaAgreementName,
                        replicationSecurity,
                        masterHostname,
                        replicaHostname,
                        Integer.parseInt(masterReplicationPort),
                        Integer.parseInt(replicaReplicationPort),
                        masterReplicationPassword,
                        replicaReplicationPassword,
                        beginReplicaNumber);

                logger.info("New replica number range: " + beginReplicaNumber + "-" + endReplicaNumber);
                dbConfig.putString("beginReplicaNumber", Integer.toString(beginReplicaNumber));

                logger.info("Initializing replication consumer");
                masterConfigurator.initializeConsumer(masterAgreementName);

            } finally {
                if (masterConn != null) masterConn.disconnect();
            }

            // remove master ldap password from password.conf (if present)

            if (!masterPassword.equals("")) {
                String passwordFile = cs.getString("passwordFile");
                ConfigStorage storage = new FileConfigStore(passwordFile);
                IConfigStore passwords = new PropConfigStore(storage);
                passwords.load();
                passwords.remove("master_internaldb");
                passwords.commit(false);
            }

            ldapConfigurator.setupDatabaseManager();

            ldapConfigurator.createVLVIndexes(subsystem);
            ldapConfigurator.rebuildVLVIndexes(subsystem);

        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    public int setupReplicationAgreements(
            LDAPConfigurator masterConfigurator,
            LDAPConfigurator replicaConfigurator,
            String masterAgreementName,
            String replicaAgreementName,
            String replicationSecurity,
            String masterHostname,
            String replicaHostname,
            int masterReplicationPort,
            int replicaReplicationPort,
            String masterReplicationPassword,
            String replicaReplicationPassword,
            int replicaID)
            throws Exception {

        String masterBindUser = "Replication Manager " + masterAgreementName;
        String replicaBindUser = "Replication Manager " + replicaAgreementName;

        logger.info("Setting up replication agreement on " + masterHostname);

        boolean created = masterConfigurator.setupReplicationAgreement(
                masterAgreementName,
                masterBindUser,
                masterReplicationPassword,
                replicaHostname,
                replicaReplicationPort,
                replicaBindUser,
                replicaReplicationPassword,
                replicationSecurity,
                replicaID);

        if (created) {
            replicaID++;
        }

        logger.info("Setting up replication agreement on " + replicaHostname);

        created = replicaConfigurator.setupReplicationAgreement(
                replicaAgreementName,
                replicaBindUser,
                replicaReplicationPassword,
                masterHostname,
                masterReplicationPort,
                masterBindUser,
                masterReplicationPassword,
                replicationSecurity,
                replicaID);

        if (created) {
            replicaID++;
        }

        return replicaID;
    }
}
