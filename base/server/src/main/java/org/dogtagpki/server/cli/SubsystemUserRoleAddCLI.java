//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.group.GroupNotFoundException;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserRoleAddCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemUserRoleAddCLI.class);

    public SubsystemUserRoleAddCLI(CLI parent) {
        super("add", "Add " + parent.getParent().getParent().getName().toUpperCase() + " user roles", parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing user ID");
        }

        String userID = cmdArgs[0];

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing role ID");
        }

        String roleID = cmdArgs[1];

        initializeTomcatJSS();
        String subsystem = parent.getParent().getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();
        ldapConfig.setMinConnections(0);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        UGSubsystem ugSubsystem = new UGSubsystem();

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);

            Group group = ugSubsystem.getGroupFromName(roleID);

            if (group == null) {
                throw new GroupNotFoundException(roleID);
            }

            ugSubsystem.addUserToGroup(group, userID);

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
