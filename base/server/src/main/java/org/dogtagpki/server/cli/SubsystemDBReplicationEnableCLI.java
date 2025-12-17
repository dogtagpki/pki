//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
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
public class SubsystemDBReplicationEnableCLI extends ServerCommandCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemDBReplicationEnableCLI.class);

    public SubsystemDBReplicationEnableCLI(CLI parent) {
        super("enable", "Enable " + parent.parent.parent.getName().toUpperCase() + " database replication", parent);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "url", true, "Database URL");
        option.setArgName("URL");
        options.addOption(option);

        option = new Option(null, "bind-dn", true, "Database bind DN");
        option.setArgName("DN");
        options.addOption(option);

        option = new Option(null, "bind-password", true, "Database bind password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "bind-password-file", true, "Database bind password file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "suffix", true, "Database suffix");
        option.setArgName("DN");
        options.addOption(option);

        option = new Option(null, "ldap-config", true, "LDAP configuration file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "replica-bind-dn", true, "Replica bind DN");
        option.setArgName("DN");
        options.addOption(option);

        option = new Option(null, "replica-bind-password", true, "Replica bind password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "replica-bind-password-file", true, "Replica bind password file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "replica-id", true, "Replica ID");
        option.setArgName("ID");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String ldapConfigFile = cmd.getOptionValue("ldap-config");
        LDAPConfig ldapConfig;
        LDAPConnectionConfig ldapConnConfig;
        LDAPAuthenticationConfig ldapAuthConfig;

        if (ldapConfigFile == null) {
            ldapConfig = new LDAPConfig();

            ldapConnConfig = ldapConfig.getConnectionConfig();
            ldapAuthConfig = ldapConfig.getAuthenticationConfig();

            String urlString = cmd.getOptionValue("url");
            if (urlString == null) {
                throw new CLIException("Missing database URL");
            }

            URI url = new URI(urlString);
            ldapConnConfig.setSecure("ldaps".equals(url.getScheme()));
            ldapConnConfig.setHostname(url.getHost());
            ldapConnConfig.setPort(url.getPort());

            String suffix = cmd.getOptionValue("suffix");
            if (suffix == null) {
                throw new CLIException("Missing database suffix");
            }

            ldapConfig.setBaseDN(suffix);

            ldapAuthConfig.setAuthType("BasicAuth");

            String bindDN = cmd.getOptionValue("bind-dn");
            if (bindDN == null) {
                throw new CLIException("Missing database bind DN");
            }

            ldapAuthConfig.setBindDN(bindDN);

            String bindPassword = cmd.getOptionValue("bind-password");
            if (bindPassword == null) {
                String bindPasswordFile = cmd.getOptionValue("bind-password-file");
                bindPassword = Files.readString(Paths.get(bindPasswordFile));
            }
            if (bindPassword == null) {
                throw new CLIException("Missing database bind password");
            }

            ldapAuthConfig.setBindPassword(bindPassword);

        } else {
            logger.info("Loading {}", ldapConfigFile);
            ConfigStorage masterConfigStorage = new FileConfigStorage(ldapConfigFile);
            ldapConfig = new LDAPConfig(masterConfigStorage);
            ldapConfig.load();

            ldapConnConfig = ldapConfig.getConnectionConfig();
            ldapAuthConfig = ldapConfig.getAuthenticationConfig();
        }

        String replicaBindDN = cmd.getOptionValue("replica-bind-dn");
        String replicaBindPassword = cmd.getOptionValue("replica-bind-password");

        if (replicaBindPassword == null) {
            String replicaBindPasswordFile = cmd.getOptionValue("replica-bind-password-file");
            replicaBindPassword = Files.readString(Paths.get(replicaBindPasswordFile));
        }

        Integer replicaID = null;
        if (cmd.hasOption("replica-id")) {
            replicaID = Integer.valueOf(cmd.getOptionValue("replica-id"));
        }

        initializeTomcatJSS();
        String subsystem = parent.parent.parent.getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        PKISocketConfig socketConfig = cs.getSocketConfig();

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
