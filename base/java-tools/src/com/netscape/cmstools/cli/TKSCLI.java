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

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.tks.TKSClient;
import com.netscape.cmstools.group.GroupCLI;
import com.netscape.cmstools.selftests.SelfTestCLI;
import com.netscape.cmstools.system.TPSConnectorCLI;
import com.netscape.cmstools.user.UserCLI;

/**
 * @author Endi S. Dewata
 */
public class TKSCLI extends SubsystemCLI {

    public TKSClient tksClient;

    public TKSCLI(CLI parent) {
        super("tks", "TKS management commands", parent);

        addModule(new GroupCLI(this));
        addModule(new SelfTestCLI(this));
        addModule(new TPSConnectorCLI(this));
        addModule(new UserCLI(this));
    }

    public SubsystemClient getSubsystemClient() throws Exception {

        if (tksClient != null) return tksClient;

        PKIClient client = getClient();
        tksClient = new TKSClient(client);

        return tksClient;
    }
}
