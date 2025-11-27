//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;

import netscape.ldap.LDAPConnection;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBReplicationEnableCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemDBReplicationEnableCLI.class);

    public SubsystemDBReplicationEnableCLI(CLI parent) {
        super("enable", "Enable " + parent.parent.parent.getName().toUpperCase() + " database replication", parent);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        options.addOption(null, "ldap-config", true, "LDAP configuration file");
        options.addOption(null, "replica-bind-dn", true, "Replica bind DN");
        options.addOption(null, "replica-bind-password-file", true, "Replica bind password file");
        options.addOption(null, "replica-id", true, "Replica ID");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String ldapConfigFile = cmd.getOptionValue("ldap-config");

        if (ldapConfigFile == null) {
            throw new CLIException("Missing LDAP configuration file");
        }

        String replicaBindDN = cmd.getOptionValue("replica-bind-dn");
        String replicaBindPasswordFile = cmd.getOptionValue("replica-bind-password-file");

        Integer replicaID = null;
        if (cmd.hasOption("replica-id")) {
            replicaID = Integer.valueOf(cmd.getOptionValue("replica-id"));
        }

        initializeTomcatJSS();
        String subsystem = parent.parent.parent.getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        PKISocketConfig socketConfig = cs.getSocketConfig();

        logger.info("Loading {}", ldapConfigFile);
        ConfigStorage masterConfigStorage = new FileConfigStorage(ldapConfigFile);
        LDAPConfig ldapConfig = new LDAPConfig(masterConfigStorage);
        ldapConfig.load();

        String replicaBindPassword = Files.readAllLines(Paths.get(replicaBindPasswordFile)).get(0);

        LDAPConnectionConfig ldapConnConfig = ldapConfig.getConnectionConfig();
        LDAPAuthenticationConfig ldapAuthConfig = ldapConfig.getAuthenticationConfig();

        PKISocketFactory socketFactory = new PKISocketFactory();
        socketFactory.setSecure(ldapConnConfig.isSecure());
        if (LdapAuthInfo.LDAP_SSLCLIENTAUTH_STR.equals(ldapAuthConfig.getAuthType())) {
            socketFactory.setClientCertNickname(ldapAuthConfig.getClientCertNickname());
        }
        socketFactory.init(socketConfig);

        LdapBoundConnFactory connFactory = new LdapBoundConnFactory("LDAPConfigurator");
        connFactory.setSocketFactory(socketFactory);
        connFactory.init(ldapConfig);
        LDAPConnection conn = connFactory.getConn();

        DatabaseConfig dbConfig = cs.getDatabaseConfig();

        try {
            LDAPConfigurator configurator = new LDAPConfigurator(conn, ldapConfig);

            boolean autoGenerateReplicaID = false;
            if (replicaID == null) {
                // auto-generate replica ID if not provided

                // TODO: remove this mechanism in the future since
                // it relies on range-based serial numbers which can
                // be problematic

                autoGenerateReplicaID = true;
                replicaID = dbConfig.getInteger("beginReplicaNumber", 1);
            }

            boolean created = configurator.enableReplication(
                    replicaBindDN,
                    replicaBindPassword,
                    replicaID);

            if (created) {
                replicaID++;
            }

            if (autoGenerateReplicaID) {
                dbConfig.putInteger("beginReplicaNumber", replicaID);
                cs.commit(false);
            }

        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}
