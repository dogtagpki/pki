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

import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.Entity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ProfileMappingClient extends Client {

    public ProfileMappingClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "profile-mappings");
    }

    public ProfileMappingCollection findProfileMappings(String filter, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, ProfileMappingCollection.class);
    }

    public ProfileMappingData getProfileMapping(String profileMappingID) throws Exception {
        return get(profileMappingID, ProfileMappingData.class);
    }

    public ProfileMappingData addProfileMapping(ProfileMappingData profileMappingData) throws Exception {
        Entity<ProfileMappingData> entity = client.entity(profileMappingData);
        return post(null, null, entity, ProfileMappingData.class);
    }

    public ProfileMappingData updateProfileMapping(String profileMappingID, ProfileMappingData profileMappingData) throws Exception {
        Entity<ProfileMappingData> entity = client.entity(profileMappingData);
        return patch(profileMappingID, null, entity, ProfileMappingData.class);
    }

    public ProfileMappingData changeProfileMappingStatus(String profileMappingID, String action) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (action != null) params.put("action", action);
        return post(profileMappingID, params, null, ProfileMappingData.class);
    }

    public void removeProfileMapping(String profileMappingID) throws Exception {
        delete(profileMappingID, Void.class);
    }
}
