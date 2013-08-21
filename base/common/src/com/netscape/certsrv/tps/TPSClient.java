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
package com.netscape.certsrv.tps;

import java.net.URISyntaxException;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.logging.ActivityClient;
import com.netscape.certsrv.token.TokenClient;
import com.netscape.certsrv.user.UserClient;

/**
 * @author Endi S. Dewata
 */
public class TPSClient extends SubsystemClient {

    public TPSClient(PKIClient client) throws Exception {
        super(client, "tps");
        init();
    }

    public void init() throws URISyntaxException {
        addClient(new ActivityClient(client, name));
        addClient(new TokenClient(client, name));
        addClient(new UserClient(client, name));
    }
}
