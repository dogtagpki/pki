//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

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
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmscore.ldapconn.PKISocketConfig;

import netscape.ldap.LDAPConnection;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBReplicationAgreementInitCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBReplicationAgreementInitCLI.class);

    public SubsystemDBReplicationAgreementInitCLI(CLI parent) {
        super(
            "init",
            "Initialize " + parent.parent.parent.parent.getName().toUpperCase() + " replication agreement",
            parent);
    }

    @Override
    public void createOptions() {

        options.addOption(null, "ldap-config", true, "LDAP configuration file");

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
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
            throw new Exception("Missing LDAP configuration file");
        }

        initializeTomcatJSS();
        String subsystem = parent.parent.parent.parent.getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        PKISocketConfig socketConfig = cs.getSocketConfig();

        logger.info("Loading {}", ldapConfigFile);
        ConfigStorage configStorage = new FileConfigStorage(ldapConfigFile);
        LDAPConfig ldapConfig = new LDAPConfig(configStorage);
        ldapConfig.load();

        LdapBoundConnFactory connFactory = new LdapBoundConnFactory("LDAPConfigurator");
        connFactory.init(socketConfig, ldapConfig);
        LDAPConnection conn = connFactory.getConn();

        try {
            LDAPConfigurator configurator = new LDAPConfigurator(conn, ldapConfig);
            configurator.initializeReplicationAgreement(agreementName);

        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}
