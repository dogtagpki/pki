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

import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.PKISocketConfig;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.UGSubsystemConfig;
import com.netscape.cmscore.usrgrp.User;
import com.netscape.cmsutil.ldap.LDAPUtil;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.password.PasswordStoreConfig;

/**
 * @author Endi S. Dewata
 */
public class SubsystemUserFindCLI extends SubsystemCLI {

    public static Logger logger = LoggerFactory.getLogger(SubsystemUserFindCLI.class);

    public SubsystemUserFindCLI(CLI parent) {
        super("find", "Find " + parent.getParent().getName().toUpperCase() + " users", parent);
    }

    @Override
    public void createOptions() {

        Option option = new Option(null, "see-also", true, "Find users linked to a certificate.");
        option.setArgName("subject DN");
        options.addOption(option);

        option = new Option(null, "output-format", true, "Output format: text (default), json.");
        option.setArgName("format");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        initializeTomcatJSS();
        String subsystem = parent.getParent().getName();
        EngineConfig cs = getEngineConfig(subsystem);
        cs.load();

        UGSubsystemConfig ugConfig = cs.getUGSubsystemConfig();
        LDAPConfig ldapConfig = ugConfig.getLDAPConfig();
        ldapConfig.putInteger("minConns", 1);

        PKISocketConfig socketConfig = cs.getSocketConfig();

        PasswordStoreConfig psc = cs.getPasswordStoreConfig();
        PasswordStore passwordStore = PasswordStore.create(psc);

        UGSubsystem ugSubsystem = new UGSubsystem();

        String filter = null;

        String seeAlso = cmd.getOptionValue("see-also");
        if (seeAlso != null) {
            filter = "(seeAlso=" + LDAPUtil.escapeFilter(seeAlso) + ")";
        }

        String outputFormat = cmd.getOptionValue("output-format", "text");

        UserCollection response = new UserCollection();

        try {
            ugSubsystem.init(ldapConfig, socketConfig, passwordStore);

            Enumeration<User> users = ugSubsystem.findUsers(filter);
            int total = 0;

            while (users.hasMoreElements()) {
                User user = users.nextElement();

                UserData userData = new UserData();

                String userID = user.getUserID();
                if (!StringUtils.isEmpty(userID)) {
                    userData.setID(userID);
                    userData.setUserID(userID);
                }

                String fullName = user.getFullName();
                if (!StringUtils.isEmpty(fullName)) userData.setFullName(fullName);

                String email = user.getEmail();
                if (!StringUtils.isEmpty(email)) userData.setEmail(email);

                String phone = user.getPhone();
                if (!StringUtils.isEmpty(phone)) userData.setPhone(phone);

                String type = user.getUserType();
                if (!StringUtils.isEmpty(type)) userData.setType(type);

                String state = user.getState();
                if (!StringUtils.isEmpty(state)) userData.setState(state);

                response.addEntry(userData);
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

            for (UserData user : response.getEntries()) {

                if (first) {
                    first = false;
                } else {
                    System.out.println();
                }

                System.out.println("  User ID: " + user.getUserID());

                String fullName = user.getFullName();
                if (!StringUtils.isEmpty(fullName)) {
                    System.out.println("  Full name: " + fullName);
                }

                String email = user.getEmail();
                if (!StringUtils.isEmpty(email)) {
                    System.out.println("  Email: " + email);
                }

                String phone = user.getPhone();
                if (!StringUtils.isEmpty(phone)) {
                    System.out.println("  Phone: " + phone);
                }

                String type = user.getType();
                if (!StringUtils.isEmpty(type)) {
                    System.out.println("  Type: " + type);
                }

                String state = user.getState();
                if (!StringUtils.isEmpty(state)) {
                    System.out.println("  State: " + state);
                }
            }

        } else {
            throw new Exception("Unsupported output format: " + outputFormat);
        }
    }
}
