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

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingClient extends Client {

    public ProfileMappingResource resource;

    public ProfileMappingClient(PKIClient client, String subsystem) throws URISyntaxException {
        super(client, subsystem, "profile-mapping");
        init();
    }

    public void init() throws URISyntaxException {
        resource = createProxy(ProfileMappingResource.class);
    }

    public ProfileMappingCollection findProfileMappings(String filter, Integer start, Integer size) {
        Response response = resource.findProfileMappings(filter, start, size);
        return client.getEntity(response, ProfileMappingCollection.class);
    }

    public ProfileMappingData getProfileMapping(String profileMappingID) {
        Response response = resource.getProfileMapping(profileMappingID);
        return client.getEntity(response, ProfileMappingData.class);
    }

    public ProfileMappingData addProfileMapping(ProfileMappingData profileMappingData) {
        Response response = resource.addProfileMapping(profileMappingData);
        return client.getEntity(response, ProfileMappingData.class);
    }

    public ProfileMappingData updateProfileMapping(String profileMappingID, ProfileMappingData profileMappingData) {
        Response response = resource.updateProfileMapping(profileMappingID, profileMappingData);
        return client.getEntity(response, ProfileMappingData.class);
    }

    public ProfileMappingData changeProfileMappingStatus(String profileMappingID, String action) {
        Response response = resource.changeStatus(profileMappingID, action);
        return client.getEntity(response, ProfileMappingData.class);
    }

    public void removeProfileMapping(String profileMappingID) {
        Response response = resource.removeProfileMapping(profileMappingID);
        client.getEntity(response, Void.class);
    }
}
