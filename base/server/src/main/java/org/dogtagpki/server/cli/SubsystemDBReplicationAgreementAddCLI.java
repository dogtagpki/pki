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
public class SubsystemDBReplicationAgreementAddCLI extends ServerCommandCLI {

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

        option = new Option(null, "replica-url", true, "Replica URL");
        option.setArgName("URL");
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

        option = new Option(null, "replication-security", true, "Replication security: SSL, TLS, None");
        option.setArgName("value");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing replication agreement name");
        }

        String agreementName = cmdArgs[0];

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

        LDAPUrl replicaUrl = new LDAPUrl(cmd.getOptionValue("replica-url"));
        String replicaBindDN = cmd.getOptionValue("replica-bind-dn");
        String replicaBindPassword = cmd.getOptionValue("replica-bind-password");

        if (replicaBindPassword == null) {
            String replicaBindPasswordFile = cmd.getOptionValue("replica-bind-password-file");
            replicaBindPassword = Files.readString(Paths.get(replicaBindPasswordFile));
        }

        String replicationSecurity = cmd.getOptionValue("replication-security");

        initializeTomcatJSS();
        String subsystem = parent.parent.parent.parent.getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        PKISocketConfig socketConfig = cs.getSocketConfig();

        String replicaHostname = replicaUrl.getHost();
        int replicaPort = replicaUrl.getPort();

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
