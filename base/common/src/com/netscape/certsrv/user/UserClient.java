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

import org.jboss.resteasy.client.ClientResponse;

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
        return userClient.findUsers(filter, start, size);
    }

    public UserData getUser(String userID) {
        return userClient.getUser(userID);
    }

    public UserData addUser(UserData userData) {
        @SuppressWarnings("unchecked")
        ClientResponse<UserData> response = (ClientResponse<UserData>)userClient.addUser(userData);
        return client.getEntity(response);
    }

    public UserData modifyUser(String userID, UserData userData) {
        @SuppressWarnings("unchecked")
        ClientResponse<UserData> response = (ClientResponse<UserData>)userClient.modifyUser(userID, userData);
        return client.getEntity(response);
    }

    public void removeUser(String userID) {
        userClient.removeUser(userID);
    }

    public UserCertCollection findUserCerts(String userID, Integer start, Integer size) {
        return userClient.findUserCerts(userID, start, size);
    }

    public UserCertData getUserCert(String userID, String certID) {
        return userClient.getUserCert(userID, certID);
    }

    public UserCertData addUserCert(String userID, UserCertData userCertData) {
        @SuppressWarnings("unchecked")
        ClientResponse<UserCertData> response = (ClientResponse<UserCertData>)userClient.addUserCert(userID, userCertData);
        return client.getEntity(response);
    }

    public void removeUserCert(String userID, String certID) {
        userClient.removeUserCert(userID, certID);
    }

    public UserMembershipCollection findUserMemberships(String userID, Integer start, Integer size) {
        return userClient.findUserMemberships(userID, start, size);
    }

    public UserMembershipData addUserMembership(String userID, String groupID) {
        @SuppressWarnings("unchecked")
        ClientResponse<UserMembershipData> response = (ClientResponse<UserMembershipData>)userClient.addUserMembership(userID, groupID);
        return client.getEntity(response);
    }

    public void removeUserMembership(String userD, String groupID) {
        userClient.removeUserMembership(userD, groupID);
    }
}
