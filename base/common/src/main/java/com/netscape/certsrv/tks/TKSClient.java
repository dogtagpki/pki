//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2013 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.tks;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.system.TPSConnectorClient;
import com.netscape.certsrv.user.UserClient;

public class TKSClient extends SubsystemClient {

    public TKSClient(PKIClient client) throws Exception {
        super(client, "tks");
        init();
    }

    public void init() throws Exception {
        addClient(new GroupClient(this));
        addClient(new SelfTestClient(client, name));
        addClient(new TPSConnectorClient(client, name));
        addClient(new UserClient(this));
    }
}
