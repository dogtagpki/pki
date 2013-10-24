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
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.logging.ActivityClient;
import com.netscape.certsrv.logging.AuditClient;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.tps.authenticator.AuthenticatorClient;
import com.netscape.certsrv.tps.cert.TPSCertClient;
import com.netscape.certsrv.tps.config.ConfigClient;
import com.netscape.certsrv.tps.connection.ConnectionClient;
import com.netscape.certsrv.tps.profile.ProfileClient;
import com.netscape.certsrv.tps.profile.ProfileMappingClient;
import com.netscape.certsrv.tps.token.TokenClient;
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
        addClient(new AuditClient(client, name));
        addClient(new AuthenticatorClient(client, name));
        addClient(new TPSCertClient(client, name));
        addClient(new ConfigClient(client, name));
        addClient(new ConnectionClient(client, name));
        addClient(new GroupClient(client, name));
        addClient(new ProfileClient(client, name));
        addClient(new ProfileMappingClient(client, name));
        addClient(new SelfTestClient(client, name));
        addClient(new TokenClient(client, name));
        addClient(new UserClient(client, name));
    }
}
