//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.Level;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

import netscape.ldap.LDAPConnection;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBReplicationSetupCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBReplicationSetupCLI.class);

    public SubsystemDBReplicationSetupCLI(CLI parent) {
        super("setup", "Set up " + parent.parent.parent.getName().toUpperCase() + " database replication", parent);
    }

    @Override
    public void createOptions() {

        options.addOption(null, "master-config", true, "Master configuration file");
        options.addOption(null, "master-replication-port", true, "Master replication port");
        options.addOption(null, "replica-replication-port", true, "Replica replication port");
        options.addOption(null, "replication-security", true, "Replication security: SSL, TLS, None");

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(Level.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(Level.INFO);
        }

        String masterConfigFile = cmd.getOptionValue("master-config");

        if (masterConfigFile == null) {
            throw new Exception("Missing master configuration file");
        }

        String masterReplicationPort = cmd.getOptionValue("master-replication-port");
        String replicaReplicationPort = cmd.getOptionValue("replica-replication-port");
        String replicationSecurity = cmd.getOptionValue("replication-security");

        initializeTomcatJSS();
        String subsystem = parent.parent.parent.getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        logger.info("Loading {}", masterConfigFile);
        ConfigStorage masterStorage = new FileConfigStorage(masterConfigFile);
        ConfigStore masterConfig = new ConfigStore(masterStorage);
        masterConfig.load();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        setupReplication(
                cs,
                passwordStore,
                masterConfig,
                masterReplicationPort,
                replicaReplicationPort,
                replicationSecurity);

        cs.commit(false);
    }

    public void setupReplication(
            EngineConfig cs,
            PasswordStore passwordStore,
            ConfigStore masterConfig,
            String masterReplicationPort,
            String replicaReplicationPort,
            String replicationSecurity) throws Exception {

        String hostname = cs.getHostname();
        String instanceID = cs.getInstanceID();

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
        LDAPConfigurator ldapConfigurator = new LDAPConfigurator(conn, ldapConfig, instanceID);

        try {
            LDAPConfig masterDBConfig = masterConfig.getSubStore("internaldb", LDAPConfig.class);
            LDAPConnectionConfig masterConnConfig = masterDBConfig.getConnectionConfig();
            String masterHostname = masterConnConfig.getString("host", "");
            String masterPort = masterConnConfig.getString("port", "");

            if (masterReplicationPort == null || masterReplicationPort.equals("")) {
                masterReplicationPort = masterPort;
            }

            String masterReplicationPassword = masterConfig.getString("internaldb.replication.password", "");
            String replicaReplicationPassword = passwordStore.getPassword("replicationdb", 0);

            // Set master LDAP password (if it exists) temporarily in password store
            // in case it is needed for replication. Not stored in password.conf.

            LDAPAuthenticationConfig masterAuthConfig = masterDBConfig.getAuthenticationConfig();
            String masterPassword = masterAuthConfig.getString("password", "");

            if (!masterPassword.equals("")) {
                masterAuthConfig.putString("bindPWPrompt", "master_internaldb");
                passwordStore.putPassword("master_internaldb", masterPassword);
                passwordStore.commit();
            }

            LdapBoundConnFactory masterFactory = new LdapBoundConnFactory("MasterLDAPConfigurator");
            masterFactory.init(socketConfig, masterDBConfig, passwordStore);

            LDAPConnection masterConn = masterFactory.getConn();
            LDAPConfigurator masterConfigurator = new LDAPConfigurator(masterConn, masterDBConfig);

            try {
                String masterAgreementName = "masterAgreement1-" + hostname + "-" + instanceID;
                String replicaAgreementName = "cloneAgreement1-" + hostname + "-" + instanceID;

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
                ConfigStorage storage = new FileConfigStorage(passwordFile);
                ConfigStore passwords = new ConfigStore(storage);
                passwords.load();
                passwords.remove("master_internaldb");
                passwords.commit(false);
            }

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
