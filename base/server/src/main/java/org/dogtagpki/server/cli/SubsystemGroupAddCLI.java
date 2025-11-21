//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;


import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
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

public class SubsystemGroupAddCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemGroupAddCLI.class);

    public SubsystemGroupAddCLI(CLI parent) {
        super("add", "Add group to " + parent.getParent().getName().toUpperCase(), parent);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "description", true, "Description");
        option.setArgName("description");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("Missing group name");
        }

        String group = cmdArgs[0];

        String description = cmd.getOptionValue("description");


        initializeTomcatJSS();
        String subsystem = parent.getParent().getName();
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
            Group groupUg = ugSubsystem.createGroup(group);

            if ( description != null && !description.isBlank() ) {
                groupUg.set(Group.ATTR_DESCRIPTION, description);
            }

            ugSubsystem.addGroup(groupUg);
        } finally {
            ugSubsystem.shutdown();
        }
    }
}
