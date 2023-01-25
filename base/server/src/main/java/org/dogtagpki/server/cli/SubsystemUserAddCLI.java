//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.password.IPasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

import netscape.ldap.LDAPAttribute;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserAddCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemUserAddCLI.class);

    public SubsystemUserAddCLI(CLI parent) {
        super("add", "Add " + parent.getParent().getName().toUpperCase() + " user", parent);
    }

    @Override
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

        option = new Option(null, "password-file", true, "Password file");
        option.setArgName("path");
        options.addOption(option);

        option = new Option(null, "phone", true, "Phone");
        option.setArgName("phone");
        options.addOption(option);

        option = new Option(null, "type", true, "Type: userType, agentType, adminType, subsystemType");
        option.setArgName("type");
        options.addOption(option);

        option = new Option(null, "state", true, "State");
        option.setArgName("state");
        options.addOption(option);

        option = new Option(null, "tps-profiles", true, "Comma-separated TPS profiles");
        option.setArgName("profiles");
        options.addOption(option);

        option = new Option(null, "attributes", true, "Attributes");
        option.setArgName("attributes");
        options.addOption(option);
    }

    @Override
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
        String passwordFile = cmd.getOptionValue("password-file");
        String phone = cmd.getOptionValue("phone");
        String type = cmd.getOptionValue("type");
        String state = cmd.getOptionValue("state");
        String tpsProfiles = cmd.getOptionValue("tps-profiles");
        String attributes = cmd.getOptionValue("attributes");

        if (passwordFile != null) {
            password = new String(Files.readAllBytes(Paths.get(passwordFile)), "UTF-8").trim();
        }

        initializeTomcatJSS();
        String subsystem = parent.getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();
        ldapConfig.putInteger("minConns", 1);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        IPasswordStore passwordStore = IPasswordStore.create(psc);

        UGSubsystem ugSubsystem = new UGSubsystem();

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);

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

            if (attributes != null) {
                String[] attrs = attributes.split(",");
                List<LDAPAttribute> ldapAttrList = new ArrayList<>();
                for (String s : attrs) {
                    String[] split = s.split(":");
                    ldapAttrList.add(new LDAPAttribute(split[0], split[1]));
                }
                user.setAttributes(ldapAttrList);
            }
            ugSubsystem.addUser(user);

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
