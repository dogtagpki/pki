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
package com.netscape.certsrv.tps.profile;

import java.net.URISyntaxException;

import org.jboss.resteasy.client.ClientResponse;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ProfileClient extends Client {

    public ProfileResource resource;

    public ProfileClient(PKIClient client) throws URISyntaxException {
        this(client, client.getSubsystem());
    }

    public ProfileClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "profile");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(ProfileResource.class);
    }

    public ProfileCollection findProfiles(Integer start, Integer size) {
        return resource.findProfiles(start, size);
    }

    public ProfileData getProfile(String profileID) {
        return resource.getProfile(profileID);
    }

    public ProfileData addProfile(ProfileData profileData) {
        @SuppressWarnings("unchecked")
        ClientResponse<ProfileData> response = (ClientResponse<ProfileData>)resource.addProfile(profileData);
        return client.getEntity(response);
    }

    public ProfileData updateProfile(String profileID, ProfileData profileData) {
        @SuppressWarnings("unchecked")
        ClientResponse<ProfileData> response = (ClientResponse<ProfileData>)resource.updateProfile(profileID, profileData);
        return client.getEntity(response);
    }

    public ProfileData changeProfileStatus(String profileID, String action) {
        @SuppressWarnings("unchecked")
        ClientResponse<ProfileData> response = (ClientResponse<ProfileData>)resource.changeProfileStatus(profileID, action);
        return client.getEntity(response);
    }

    public void removeProfile(String profileID) {
        resource.removeProfile(profileID);
    }
}
