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
package com.netscape.certsrv.profile;

import java.net.URISyntaxException;

import org.jboss.resteasy.client.ClientResponse;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Ade Lee
 */
public class ProfileClient extends Client {

    public ProfileResource profileClient;

    public ProfileClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "profile");
        init();
    }

    public void init() throws URISyntaxException {
        profileClient = createProxy(ProfileResource.class);
    }

    public ProfileData retrieveProfile(String id) {
        return profileClient.retrieveProfile(id);
    }

    public ProfileDataInfos listProfiles(Integer start, Integer size) {
        return profileClient.listProfiles(start, size);
    }

    public void enableProfile(String id) {
        profileClient.modifyProfileState(id, "enable");
    }

    public void disableProfile(String id) {
        profileClient.modifyProfileState(id, "disable");
    }

    public ProfileData createProfile(ProfileData data) {
        @SuppressWarnings("unchecked")
        ClientResponse<ProfileData> response =
                (ClientResponse<ProfileData>) profileClient.createProfile(data);
        return client.getEntity(response);
    }

    public ProfileData modifyProfile(ProfileData data) {
        @SuppressWarnings("unchecked")
        ClientResponse<ProfileData> response =
                (ClientResponse<ProfileData>) profileClient.modifyProfile(data.getId(), data);
        return client.getEntity(response);
    }

    public void deleteProfile(String id) {
        profileClient.deleteProfile(id);
    }

}
