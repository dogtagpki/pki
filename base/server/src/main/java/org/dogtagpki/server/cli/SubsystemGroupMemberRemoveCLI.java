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

import com.netscape.cmscore.apps.CMS;
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
public class SubsystemGroupMemberRemoveCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemGroupMemberRemoveCLI.class);

    public SubsystemGroupMemberRemoveCLI(CLI parent) {
        super("del", "Remove " + parent.getParent().getParent().getName().toUpperCase() + " group member", parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing group ID");
        }

        if (cmdArgs.length < 2) {
            throw new CLIException("Missing member ID");
        }

        String groupID = cmdArgs[0];
        String memberID = cmdArgs[1];

        initializeTomcatJSS();
        String subsystem = parent.getParent().getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();
        ldapConfig.setMinConnections(0);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = CMS.createPasswordStore(psc);

        UGSubsystem ugSubsystem = new UGSubsystem();

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);

            Group group = ugSubsystem.getGroupFromName(groupID);

            if (group == null) {
                throw new CLIException("Group " + groupID + " not found");
            }

            ugSubsystem.removeUserFromGroup(group, memberID);

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
