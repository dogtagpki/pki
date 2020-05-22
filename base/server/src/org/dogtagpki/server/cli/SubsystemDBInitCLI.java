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

import com.netscape.cms.servlet.csadmin.LDAPConfigurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.IPasswordStore;

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
        options.addOption(null, "setup-db-manager", false, "Set up database manager");
        options.addOption(null, "setup-vlv-indexes", false, "Set up VLV indexes");

        options.addOption("v", "verbose", false, "Run in verbose mode.");
        options.addOption(null, "debug", false, "Run in debug mode.");
        options.addOption(null, "help", false, "Show help message.");
    }

    public void execute(CommandLine cmd) throws Exception {

        String catalinaBase = System.getProperty("catalina.base");
        String serverXml = catalinaBase + "/conf/server.xml";

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadTomcatConfig(serverXml);
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
        String pwdClass = cs.getString("passwordClass");
        String pwdPath = cs.getString("passwordFile", null);

        logger.info("Creating " + pwdClass);
        IPasswordStore passwordStore = (IPasswordStore) Class.forName(pwdClass).newInstance();
        passwordStore.init(pwdPath);
        passwordStore.setId(instanceId);

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

        PKISocketFactory socketFactory;
        if (authInfo.getAuthType() == LdapAuthInfo.LDAP_AUTHTYPE_SSLCLIENTAUTH) {
            socketFactory = new PKISocketFactory(authInfo.getClientCertNickname());
        } else {
            socketFactory = new PKISocketFactory(connInfo.getSecure());
        }
        socketFactory.init(cs);

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

            if (cmd.hasOption("setup-db-manager")) {
                ldapConfigurator.setupDatabaseManager();
            }

            if (cmd.hasOption("setup-vlv-indexes")) {
                ldapConfigurator.createVLVIndexes(subsystem);
                ldapConfigurator.rebuildVLVIndexes(subsystem);
            }

        } finally {
            conn.disconnect();
        }
    }
}
