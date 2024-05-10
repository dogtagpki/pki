//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.util.Enumeration;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CLIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.UserNotFoundException;
import com.netscape.certsrv.user.UserMembershipCollection;
import com.netscape.certsrv.user.UserMembershipData;
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
public class SubsystemUserRoleFindCLI extends SubsystemCLI {

    public static final Logger logger = LoggerFactory.getLogger(SubsystemUserRoleFindCLI.class);

    public SubsystemUserRoleFindCLI(CLI parent) {
        super("find", "Find " + parent.getParent().getParent().getName().toUpperCase() + " user roles", parent);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new CLIException("Missing user ID");
        }

        String userID = cmdArgs[0];

        String outputFormat = cmd.getOptionValue("output-format", "text");

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
        UserMembershipCollection response = new UserMembershipCollection();

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);

            User user = ugSubsystem.getUser(userID);

            if (user == null) {
                throw new UserNotFoundException(userID);
            }

            Enumeration<Group> groups = ugSubsystem.findGroupsByUser(user.getUserDN(), null);

            int total = 0;

            while (groups.hasMoreElements()) {
                Group group = groups.nextElement();

                UserMembershipData userRole = new UserMembershipData();
                userRole.setID(group.getGroupID());
                userRole.setUserID(userID);

                response.addEntry(userRole);
                total++;
            }

            response.setTotal(total);

        } finally {
            ugSubsystem.shutdown();
        }

        if (outputFormat.equalsIgnoreCase("json")) {
            System.out.println(response.toJSON());

        } else if (outputFormat.equalsIgnoreCase("text")) {

            boolean first = true;

            for (UserMembershipData userRole : response.getEntries()) {

                if (first) {
                    first = false;
                } else {
                    System.out.println();
                }

                System.out.println("  Role ID: " + userRole.getID());
            }

        } else {
            throw new CLIException("Unsupported output format: " + outputFormat);
        }
    }
}
