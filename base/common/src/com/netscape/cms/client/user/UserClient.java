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
package com.netscape.cms.client.user;

import java.net.URISyntaxException;

import org.jboss.resteasy.client.ClientResponse;

import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserCertResource;
import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserResource;
import com.netscape.cms.client.ClientConfig;
import com.netscape.cms.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class UserClient extends PKIClient {

    public UserResource userClient;
    public UserCertResource userCertClient;

    public UserClient(ClientConfig config) throws URISyntaxException {
        super(config);

        userClient = createProxy(UserResource.class);
        userCertClient = createProxy(UserCertResource.class);
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
        return getEntity(response);
    }

    public UserData modifyUser(String userID, UserData userData) {
        @SuppressWarnings("unchecked")
        ClientResponse<UserData> response = (ClientResponse<UserData>)userClient.modifyUser(userID, userData);
        return getEntity(response);
    }

    public void removeUser(String userID) {
        userClient.removeUser(userID);
    }

    public UserCertCollection findUserCerts(String userID, Integer start, Integer size) {
        return userCertClient.findUserCerts(userID, start, size);
    }

    public UserCertData getUserCert(String userID, String certID) {
        return userCertClient.getUserCert(userID, certID);
    }

    public UserCertData addUserCert(String userID, UserCertData userCertData) {
        @SuppressWarnings("unchecked")
        ClientResponse<UserCertData> response = (ClientResponse<UserCertData>)userCertClient.addUserCert(userID, userCertData);
        return getEntity(response);
    }

    public void removeUserCert(String userID, String certID) {
        userCertClient.removeUserCert(userID, certID);
    }
}
