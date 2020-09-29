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

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ProfileClient extends Client {

    public ProfileResource resource;

    public ProfileClient(PKIClient client) throws Exception {
        this(client, client.getSubsystem());
    }

    public ProfileClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "profile");
        init();
    }

    public void init() throws Exception {
        resource = createProxy(ProfileResource.class);
    }

    public ProfileCollection findProfiles(String filter, Integer start, Integer size) throws Exception {
        Response response = resource.findProfiles(filter, start, size);
        return client.getEntity(response, ProfileCollection.class);
    }

    public ProfileData getProfile(String profileID) throws Exception {
        Response response = resource.getProfile(profileID);
        return client.getEntity(response, ProfileData.class);
    }

    public ProfileData addProfile(ProfileData profileData) throws Exception {
        Response response = resource.addProfile(profileData);
        return client.getEntity(response, ProfileData.class);
    }

    public ProfileData updateProfile(String profileID, ProfileData profileData) throws Exception {
        Response response = resource.updateProfile(profileID, profileData);
        return client.getEntity(response, ProfileData.class);
    }

    public ProfileData changeProfileStatus(String profileID, String action) throws Exception {
        Response response = resource.changeStatus(profileID, action);
        return client.getEntity(response, ProfileData.class);
    }

    public void removeProfile(String profileID) throws Exception {
        Response response = resource.removeProfile(profileID);
        client.getEntity(response, Void.class);
    }
}
