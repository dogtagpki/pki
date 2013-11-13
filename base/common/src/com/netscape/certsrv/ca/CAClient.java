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
//(C) 2012 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.ca;

import java.net.URISyntaxException;

import com.netscape.certsrv.cert.CertClient;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.group.GroupClient;
import com.netscape.certsrv.logging.AuditClient;
import com.netscape.certsrv.profile.ProfileData;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.certsrv.profile.ProfileResource;
import com.netscape.certsrv.selftests.SelfTestClient;
import com.netscape.certsrv.user.UserClient;

public class CAClient extends SubsystemClient {

    private ProfileResource profileClient;

    public CAClient(PKIClient client) throws URISyntaxException {
        super(client, "ca");
        init();
    }

    public void init() throws URISyntaxException {

        addClient(new AuditClient(client, name));
        addClient(new CertClient(client, name));
        addClient(new GroupClient(client, name));
        addClient(new SelfTestClient(client, name));
        addClient(new UserClient(client, name));

        profileClient = createProxy(ProfileResource.class);
    }

    public ProfileDataInfos listProfiles(Integer start, Integer size) {
        return profileClient.listProfiles(start, size);
    }

    public ProfileData getProfile(String id) {

        if (id == null) {
            return null;
        }

        return profileClient.retrieveProfile(id);
    }
}
