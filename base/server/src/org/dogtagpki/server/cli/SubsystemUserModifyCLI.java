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

import com.netscape.certsrv.user.UserCollection;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStore;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LDAPConnectionConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.ldapconn.PKISocketFactory;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserModifyCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemUserModifyCLI.class);

    public SubsystemUserModifyCLI(CLI parent) {
        super("mod", "Modify " + parent.getParent().getName().toUpperCase() + " user", parent);
    }

    public void createOptions() {

        Option option = new Option(null, "add-see-also", true, "Link user to a certificate.");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option(null, "del-see-also", true, "Unlink user to a certificate.");
        option.setArgName("subject DN");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing user ID");
        }

        String userID = cmdArgs[0];

        String catalinaBase = System.getProperty("catalina.base");
        String serverXml = catalinaBase + "/conf/server.xml";

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadTomcatConfig(serverXml);
        tomcatjss.init();

        String subsystem = parent.getParent().getName();
        String configDir = catalinaBase + File.separator + subsystem;
        String configFile = configDir+ File.separator + "conf" + File.separator + CMS.CONFIG_FILE;

        logger.info("Loading " + configFile);
        ConfigStorage storage = new FileConfigStore(configFile);
        EngineConfig cs = new EngineConfig(storage);
        cs.load();
        LDAPConfig ldapConfig = cs.getInternalDBConfig();

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

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        UGSubsystem ugSubsystem = new UGSubsystem();

        String addSeeAlso = cmd.getOptionValue("add-see-also");
        String delSeeAlso = cmd.getOptionValue("del-see-also");

        UserCollection response = new UserCollection();

        try {
            ugSubsystem.init(socketConfig, ugConfig, passwordStore);

            if (addSeeAlso != null) {
                ugSubsystem.addSeeAlso(userID, addSeeAlso);
            }

            if (delSeeAlso != null) {
                ugSubsystem.removeSeeAlso(userID, delSeeAlso);
            }

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
