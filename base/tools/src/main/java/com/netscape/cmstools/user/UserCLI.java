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

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCLI;

/**
 * @author Endi S. Dewata
 */
public class UserCLI extends CLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserCLI.class);

    public SubsystemCLI subsystemCLI;

    public UserCLI(SubsystemCLI subsystemCLI) {
        super("user", "User management commands", subsystemCLI);
        this.subsystemCLI = subsystemCLI;

        addModule(new UserFindCLI(this));
        addModule(new UserShowCLI(this));
        addModule(new UserAddCLI(this));
        addModule(new UserModifyCLI(this));
        addModule(new UserRemoveCLI(this));

        addModule(new UserCertCLI(this));

        addModule(new UserMembershipCLI(this));
    }

    @Override
    public String getFullName() {
        // do not include MainCLI's name
        return parent instanceof MainCLI ? name : parent.getFullName() + "-" + name;
    }

    @Override
    public String getManPage() {
        return "pki-user";
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

        String tpsProfiles = userData.getAttribute(UserResource.ATTR_TPS_PROFILES);
        if (tpsProfiles != null) {
            System.out.println("  TPS Profiles:");
            for (String profile: tpsProfiles.split(",")) {
                System.out.println("    " + profile);
            }
        }
    }
}
