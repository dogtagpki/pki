//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

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
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapBoundConnection;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmsutil.password.IPasswordStore;

/**
 * @author Endi S. Dewata
 */
public class SubsystemDBEmptyCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemDBEmptyCLI.class);

    public SubsystemDBEmptyCLI(CLI parent) {
        super("empty", "Empty " + parent.getParent().getName().toUpperCase() + " database", parent);
    }

    public void createOptions() {

        Option option = new Option("d", true, "NSS database location");
        option.setArgName("database");
        options.addOption(option);

        option = new Option("f", true, "NSS database password configuration");
        option.setArgName("password config");
        options.addOption(option);

        options.addOption(null, "force", false, "Force");

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

        logger.info("Emptying database " + database);

        if (!cmd.hasOption("force")) {
            System.out.println("WARNING: This command will remove the " + baseDN + " subtree.");
            System.out.println();
            System.out.print("Are you sure (y/N)? ");
            System.out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String line = reader.readLine();
            if (!line.equalsIgnoreCase("Y")) {
                return;
            }
        }

        String instanceId = cs.getInstanceID();
        String pwdClass = cs.getString("passwordClass");
        String pwdPath = cs.getString("passwordFile", null);

        logger.info("Creating " + pwdClass);
        IPasswordStore passwordStore = (IPasswordStore) Class.forName(pwdClass).newInstance();
        passwordStore.init(pwdPath);
        passwordStore.setId(instanceId);

        IConfigStore connConfig = ldapConfig.getSubStore("ldapconn");
        IConfigStore authConfig = ldapConfig.getSubStore("ldapauth");

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
            ldapConfigurator.deleteEntry(baseDN);

        } finally {
            conn.disconnect();
        }
    }
}
