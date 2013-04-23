// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.user;

import java.util.Arrays;

import org.apache.commons.lang.StringUtils;
import org.jboss.resteasy.plugins.providers.atom.Link;

import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserClient;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserMembershipData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class UserCLI extends CLI {

    public MainCLI parent;
    public UserClient client;

    public UserCLI(MainCLI parent) {
        super("user", "User management commands");
        this.parent = parent;

        addModule(new UserFindCLI(this));
        addModule(new UserShowCLI(this));
        addModule(new UserAddCLI(this));
        addModule(new UserModifyCLI(this));
        addModule(new UserRemoveCLI(this));

        addModule(new UserFindCertCLI(this));
        addModule(new UserShowCertCLI(this));
        addModule(new UserAddCertCLI(this));
        addModule(new UserRemoveCertCLI(this));

        addModule(new UserFindMembershipCLI(this));
        addModule(new UserAddMembershipCLI(this));
        addModule(new UserRemoveMembershipCLI(this));
    }

    public void printHelp() {

        System.out.println("Commands:");

        int leftPadding = 1;
        int rightPadding = 25;

        for (CLI module : modules.values()) {
            String label = name + "-" + module.getName();

            int padding = rightPadding - leftPadding - label.length();
            if (padding < 1)
                padding = 1;

            System.out.print(StringUtils.repeat(" ", leftPadding));
            System.out.print(label);
            System.out.print(StringUtils.repeat(" ", padding));
            System.out.println(module.getDescription());
        }
    }

    public void execute(String[] args) throws Exception {

        client = new UserClient(parent.client);

        if (args.length == 0) {
            printHelp();
            System.exit(1);
        }

        String command = args[0];
        String[] commandArgs = Arrays.copyOfRange(args, 1, args.length);

        if (command == null) {
            printHelp();
            System.exit(1);
        }

        CLI module = getModule(command);
        if (module != null) {
            module.execute(commandArgs);

        } else {
            System.err.println("Error: Invalid command \"" + command + "\"");
            printHelp();
            System.exit(1);
        }
    }

    public static void printUser(UserData userData) {
        System.out.println("  User ID: " + userData.getID());

        String fullName = userData.getFullName();
        if (!StringUtils.isEmpty(fullName))
            System.out.println("  Full name: " + fullName);

        String email = userData.getEmail();
        if (!StringUtils.isEmpty(email))
            System.out.println("  Email: " + email);

        String phone = userData.getPhone();
        if (!StringUtils.isEmpty(phone))
            System.out.println("  Phone: " + phone);

        String type = userData.getType();
        if (!StringUtils.isEmpty(type))
            System.out.println("  Type: " + type);

        String state = userData.getState();
        if (!StringUtils.isEmpty(state))
            System.out.println("  State: " + state);

        Link link = userData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }

    public static void printCert(
            UserCertData userCertData,
            boolean showPrettyPrint,
            boolean showEncoded) {

        System.out.println("  Cert ID: " + userCertData.getID());
        System.out.println("  Version: " + userCertData.getVersion());
        System.out.println("  Serial Number: " + userCertData.getSerialNumber().toHexString());
        System.out.println("  Issuer: " + userCertData.getIssuerDN());
        System.out.println("  Subject: " + userCertData.getSubjectDN());

        Link link = userCertData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }

        String prettyPrint = userCertData.getPrettyPrint();
        if (showPrettyPrint && prettyPrint != null) {
            System.out.println();
            System.out.println(prettyPrint);
        }

        String encoded = userCertData.getEncoded();
        if (showEncoded && encoded != null) {
            System.out.println();
            System.out.println(encoded);
        }
    }

    public static void printUserMembership(UserMembershipData userMembershipData) {
        System.out.println("  Group: "+userMembershipData.getID());

        Link link = userMembershipData.getLink();
        if (verbose && link != null) {
            System.out.println("  Link: " + link.getHref());
        }
    }
}
