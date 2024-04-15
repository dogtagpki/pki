//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.BufferedReader;
import java.io.FileReader;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserModifyCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemUserModifyCLI.class);

    public SubsystemUserModifyCLI(CLI parent) {
        super("mod", "Modify " + parent.getParent().getName().toUpperCase() + " user", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "password", true, "User password");
        option.setArgName("password");
        options.addOption(option);

        option = new Option(null, "password-file", true, "User password file");
        option.setArgName("password-file");
        options.addOption(option);

        option = new Option(null, "add-see-also", true, "Link user to a certificate.");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option(null, "del-see-also", true, "Unlink user to a certificate.");
        option.setArgName("subject DN");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing user ID");
        }

        String userID = cmdArgs[0];

        initializeTomcatJSS();
        String subsystem = parent.getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();
        ldapConfig.setMinConnections(0);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        UGSubsystem ugSubsystem = new UGSubsystem();

        String password = cmd.getOptionValue("password");
        String passwordFile = cmd.getOptionValue("password-file");

        if (passwordFile != null) {
            try (BufferedReader br = new BufferedReader(new FileReader(passwordFile))) {
                password = br.readLine();
            }
        }

        String addSeeAlso = cmd.getOptionValue("add-see-also");
        String delSeeAlso = cmd.getOptionValue("del-see-also");

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);
            User user = ugSubsystem.getUser(userID);

            if (user == null) {
                throw new CLIException("User not found: " + userID);
            }

            if (password != null) {
                user.setPassword(password);
                ugSubsystem.modifyUser(user);
            }

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
