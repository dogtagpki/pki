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
import org.dogtagpki.util.logging.PKILogger;
import org.dogtagpki.util.logging.PKILogger.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
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
import netscape.ldap.LDAPUrl;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBReplicationAgreementAddCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemDBReplicationAgreementAddCLI.class);

    public SubsystemDBReplicationAgreementAddCLI(CLI parent) {
        super(
            "add",
            "Add " + parent.parent.parent.parent.getName().toUpperCase() + " replication agreement",
            parent);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        options.addOption(null, "ldap-config", true, "LDAP configuration file");
        options.addOption(null, "replica-url", true, "Replica URL");
        options.addOption(null, "replica-bind-dn", true, "Replica bind DN");
        options.addOption(null, "replica-bind-password-file", true, "Replica bind password file");
        options.addOption(null, "replication-security", true, "Replication security: SSL, TLS, None");
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing replication agreement name");
        }

        String agreementName = cmdArgs[0];

        if (cmd.hasOption("debug")) {
            PKILogger.setLevel(LogLevel.DEBUG);

        } else if (cmd.hasOption("verbose")) {
            PKILogger.setLevel(LogLevel.INFO);
        }

        String ldapConfigFile = cmd.getOptionValue("ldap-config");

        if (ldapConfigFile == null) {
            throw new CLIException("Missing LDAP configuration file");
        }

        LDAPUrl replicaUrl = new LDAPUrl(cmd.getOptionValue("replica-url"));
        String replicaBindDN = cmd.getOptionValue("replica-bind-dn");
        String replicaBindPasswordFile = cmd.getOptionValue("replica-bind-password-file");
        String replicationSecurity = cmd.getOptionValue("replication-security");

        initializeTomcatJSS();
        String subsystem = parent.parent.parent.parent.getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        PKISocketConfig socketConfig = cs.getSocketConfig();

        logger.info("Loading {}", ldapConfigFile);
        ConfigStorage masterConfigStorage = new FileConfigStorage(ldapConfigFile);
        LDAPConfig ldapConfig = new LDAPConfig(masterConfigStorage);
        ldapConfig.load();

        String replicaHostname = replicaUrl.getHost();
        int replicaPort = replicaUrl.getPort();

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

        try {
            LDAPConfigurator configurator = new LDAPConfigurator(conn, ldapConfig);

            configurator.createReplicationAgreement(
                    agreementName,
                    replicaHostname,
                    replicaPort,
                    replicaBindDN,
                    replicaBindPassword,
                    replicationSecurity);

        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}
