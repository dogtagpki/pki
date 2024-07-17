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
package com.netscape.certsrv.user;

import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.client.Entity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;

/**
 * @author Endi S. Dewata
 */
public class UserClient extends Client {

    public UserClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "admin/users");
    }

    public UserClient(SubsystemClient subsystemClient) throws Exception {
        this(subsystemClient.client, subsystemClient.getName());
    }

    public UserCollection findUsers(String filter, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, UserCollection.class);
    }

    public UserData getUser(String userID) throws Exception {
        return get(userID, UserData.class);
    }

    public UserData addUser(UserData userData) throws Exception {
        Entity<UserData> entity = client.entity(userData);
        return post(null, null, entity, UserData.class);
    }

    public UserData modifyUser(String userID, UserData userData) throws Exception {
        Entity<UserData> entity = client.entity(userData);
        return patch(userID, null, entity, UserData.class);
    }

    public void removeUser(String userID) throws Exception {
        delete(userID, Void.class);
    }

    public UserCertCollection findUserCerts(String userID, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(userID + "/certs", params, UserCertCollection.class);
    }

    public UserCertData getUserCert(String userID, String certID) throws Exception {
        return get(userID + "/certs/" + certID, UserCertData.class);
    }

    public UserCertData addUserCert(String userID, UserCertData userCertData) throws Exception {
        Entity<UserCertData> entity = client.entity(userCertData);
        return post(userID + "/certs", null, entity, UserCertData.class);
    }

    public void removeUserCert(String userID, String certID) throws Exception {
        delete(userID + "/certs/" + certID, Void.class);
    }

    public UserMembershipCollection findUserMemberships(String userID, String filter, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(userID + "/memberships", params, UserMembershipCollection.class);
    }

    public UserMembershipData addUserMembership(String userID, String groupID) throws Exception {
        Entity<String> entity = client.entity(groupID);
        return post(userID + "/memberships", null, entity, UserMembershipData.class);
    }

    public void removeUserMembership(String userD, String groupID) throws Exception {
        delete(userD + "/memberships/" + groupID, Void.class);
    }
}
