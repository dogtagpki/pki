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

import com.netscape.certsrv.ca.CAClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.cmstools.authority.AuthorityCLI;
import com.netscape.cmstools.cert.CertCLI;
import com.netscape.cmstools.feature.FeatureCLI;
import com.netscape.cmstools.group.GroupCLI;
import com.netscape.cmstools.profile.ProfileCLI;
import com.netscape.cmstools.selftests.SelfTestCLI;
import com.netscape.cmstools.system.KRAConnectorCLI;
import com.netscape.cmstools.user.UserCLI;

/**
 * @author Endi S. Dewata
 */
public class CACLI extends SubsystemCLI {

    public CAClient caClient;

    public CACLI(CLI parent) {
        super("ca", "CA management commands", parent);

        addModule(new AuthorityCLI(this));
        addModule(new CertCLI(this));
        addModule(new FeatureCLI(this));
        addModule(new GroupCLI(this));
        addModule(new KRAConnectorCLI(this));
        addModule(new ProfileCLI(this));
        addModule(new SelfTestCLI(this));
        addModule(new UserCLI(this));
    }

    public SubsystemClient getSubsystemClient() throws Exception {

        if (caClient != null) return caClient;

        PKIClient client = getClient();
        caClient = new CAClient(client);

        return caClient;
    }
}
