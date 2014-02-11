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

import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class UserClient extends Client {

    public UserResource userClient;

    public UserClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "user");
        init();
    }

    public void init() throws URISyntaxException {
        userClient = createProxy(UserResource.class);
    }

    public UserCollection findUsers(String filter, Integer start, Integer size) {
        Response response = userClient.findUsers(filter, start, size);
        return client.getEntity(response, UserCollection.class);
    }

    public UserData getUser(String userID) {
        Response response = userClient.getUser(userID);
        return client.getEntity(response, UserData.class);
    }

    public UserData addUser(UserData userData) {
        Response response = userClient.addUser(userData);
        return client.getEntity(response, UserData.class);
    }

    public UserData modifyUser(String userID, UserData userData) {
        Response response = userClient.modifyUser(userID, userData);
        return client.getEntity(response, UserData.class);
    }

    public void removeUser(String userID) {
        Response response = userClient.removeUser(userID);
        client.getEntity(response, Void.class);
    }

    public UserCertCollection findUserCerts(String userID, Integer start, Integer size) {
        Response response = userClient.findUserCerts(userID, start, size);
        return client.getEntity(response, UserCertCollection.class);
    }

    public UserCertData getUserCert(String userID, String certID) {
        Response response = userClient.getUserCert(userID, certID);
        return client.getEntity(response, UserCertData.class);
    }

    public UserCertData addUserCert(String userID, UserCertData userCertData) {
        Response response = userClient.addUserCert(userID, userCertData);
        return client.getEntity(response, UserCertData.class);
    }

    public void removeUserCert(String userID, String certID) {
        Response response = userClient.removeUserCert(userID, certID);
        client.getEntity(response, Void.class);
    }

    public UserMembershipCollection findUserMemberships(String userID, Integer start, Integer size) {
        Response response = userClient.findUserMemberships(userID, start, size);
        return client.getEntity(response, UserMembershipCollection.class);
    }

    public UserMembershipData addUserMembership(String userID, String groupID) {
        Response response = userClient.addUserMembership(userID, groupID);
        return client.getEntity(response, UserMembershipData.class);
    }

    public void removeUserMembership(String userD, String groupID) {
        Response response = userClient.removeUserMembership(userD, groupID);
        client.getEntity(response, Void.class);
    }
}
