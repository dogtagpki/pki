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
 * Add one user to multiple groups in a single JVM/LDAP session.
 */
public class SubsystemGroupMemberAddBatchCLI extends ServerCommandCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemGroupMemberAddBatchCLI.class);

    public SubsystemGroupMemberAddBatchCLI(CLI parent) {
        super("add-batch", "Add " + parent.getParent().getParent().getName().toUpperCase()
                + " group member to multiple groups", parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing member ID");
        }

        if (cmdArgs.length < 2) {
            throw new CLIException("Missing group ID");
        }

        String memberID = cmdArgs[0];

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

            for (int i = 1; i < cmdArgs.length; i++) {
                String groupID = cmdArgs[i];

                Group group = ugSubsystem.getGroupFromName(groupID);

                if (group == null) {
                    throw new GroupNotFoundException(groupID);
                }

                group.addMemberName(memberID);
                ugSubsystem.modifyGroup(group);
            }

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
