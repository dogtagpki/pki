//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.tomcat.util.net.jss.TomcatJSS;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.user.UserData;
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
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserAddCLI extends CommandCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemUserAddCLI.class);

    public SubsystemUserAddCLI(CLI parent) {
        super("add", "Add " + parent.getParent().getName().toUpperCase() + " user", parent);
    }

    public void createOptions() {

        Option option = new Option(null, "full-name", true, "Full name");
        option.setArgName("full name");
        options.addOption(option);

        option = new Option(null, "email", true, "Email");
        option.setArgName("email");
        options.addOption(option);

        option = new Option(null, "password", true, "Password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "phone", true, "Phone");
        option.setArgName("phone");
        options.addOption(option);

        option = new Option(null, "type", true, "Type");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "state", true, "State");
        option.setArgName("state");
        options.addOption(option);

        option = new Option(null, "tps-profiles", true, "Comma-separated TPS profiles");
        option.setArgName("profiles");
        options.addOption(option);
    }

    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing user ID");
        }

        String userID = cmdArgs[0];

        String fullName = cmd.getOptionValue("full-name");

        if (fullName == null) {
            throw new Exception("Missing full name");
        }

        String email = cmd.getOptionValue("email");
        String password = cmd.getOptionValue("password");
        String phone = cmd.getOptionValue("phone");
        String type = cmd.getOptionValue("type");
        String state = cmd.getOptionValue("state");
        String tpsProfiles = cmd.getOptionValue("tps-profiles");

        String catalinaBase = System.getProperty("catalina.base");

        TomcatJSS tomcatjss = TomcatJSS.getInstance();
        tomcatjss.loadConfig();
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

        UserData userData = new UserData();

        try {
            ugSubsystem.init(socketConfig, ugConfig, passwordStore);

            User user = new User();
            user.setUserID(userID);
            user.setFullName(fullName);
            user.setEmail(email);
            user.setPassword(password);
            user.setPhone(phone);
            user.setUserType(type);
            user.setState(state);

            if (tpsProfiles != null) {
                List<String> list = Arrays.asList(tpsProfiles.split(","));
                user.setTpsProfiles(list);
            }

            ugSubsystem.addUser(user);

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
