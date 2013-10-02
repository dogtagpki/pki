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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cmstools.cli;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.tps.TPSClient;
import com.netscape.cmstools.group.GroupCLI;
import com.netscape.cmstools.logging.ActivityCLI;
import com.netscape.cmstools.logging.AuditCLI;
import com.netscape.cmstools.selftests.SelfTestCLI;
import com.netscape.cmstools.tps.authenticator.AuthenticatorCLI;
import com.netscape.cmstools.tps.cert.TPSCertCLI;
import com.netscape.cmstools.tps.config.ConfigCLI;
import com.netscape.cmstools.tps.connection.ConnectionCLI;
import com.netscape.cmstools.tps.profile.ProfileCLI;
import com.netscape.cmstools.tps.token.TokenCLI;
import com.netscape.cmstools.user.UserCLI;

/**
 * @author Endi S. Dewata
 */
public class TPSCLI extends SubsystemCLI {

    public TPSClient tpsClient;

    public TPSCLI(MainCLI mainCLI) {
        super("tps", "TPS management commands", mainCLI);

        addModule(new ActivityCLI(this));
        addModule(new AuditCLI(this));
        addModule(new AuthenticatorCLI(this));
        addModule(new TPSCertCLI(this));
        addModule(new ConfigCLI(this));
        addModule(new ConnectionCLI(this));
        addModule(new GroupCLI(this));
        addModule(new ProfileCLI(this));
        addModule(new SelfTestCLI(this));
        addModule(new TokenCLI(this));
        addModule(new UserCLI(this));
    }

    public String getFullName() {
        if (parent instanceof MainCLI) {
            // do not include MainCLI's name
            return name;
        } else {
            return parent.getFullName() + "-" + name;
        }
    }

    public void init() throws Exception {
        client = parent.getClient();
        tpsClient = new TPSClient(client);
    }

    public void login() {
        tpsClient.login();
    }

    public void logout() {
        tpsClient.logout();
    }

    public Client getClient(String name) {
        return tpsClient.getClient(name);
    }
}
