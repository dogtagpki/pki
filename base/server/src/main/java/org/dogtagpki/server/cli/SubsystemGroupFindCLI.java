//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.util.Enumeration;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.lang3.StringUtils;
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
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemGroupFindCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemGroupFindCLI.class);

    public SubsystemGroupFindCLI(CLI parent) {
        super("find", "Find " + parent.getParent().getName().toUpperCase() + " groups", parent);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "member", true, "Member ID");
        option.setArgName("ID");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {


        String memberID = cmd.getOptionValue("member");

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

            Enumeration<Group> groups;
            if (memberID != null) {
                User member = ugSubsystem.getUser(memberID);
                groups = ugSubsystem.findGroupsByUser(member.getUserDN(), null);

            } else {
                groups = ugSubsystem.listGroups(null);
            }

            boolean first = true;

            while (groups.hasMoreElements()) {
                Group group = groups.nextElement();

                if (first) {
                    first = false;
                } else {
                    System.out.println();
                }

                System.out.println("  Group ID: " + group.getGroupID());

                String description = group.getDescription();
                if (!StringUtils.isEmpty(description)) {
                    System.out.println("  Description: " + description);
                }
            }

        } finally {
            ugSubsystem.shutdown();
        }
    }
}
