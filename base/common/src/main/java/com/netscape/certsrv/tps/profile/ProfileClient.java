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
public class ProfileClient extends Client {

    public ProfileClient(PKIClient client) throws Exception {
        this(client, client.getSubsystem());
    }

    public ProfileClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "profiles");
    }

    public ProfileCollection findProfiles(String filter, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, ProfileCollection.class);
    }

    public ProfileData getProfile(String profileID) throws Exception {
        return get(profileID, ProfileData.class);
    }

    public ProfileData addProfile(ProfileData profileData) throws Exception {
        Entity<ProfileData> entity = client.entity(profileData);
        return post(null, null, entity, ProfileData.class);
    }

    public ProfileData updateProfile(String profileID, ProfileData profileData) throws Exception {
        Entity<ProfileData> entity = client.entity(profileData);
        return patch(profileID, null, entity, ProfileData.class);
    }

    public ProfileData changeProfileStatus(String profileID, String action) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (action != null) params.put("action", action);
        return post(profileID, params, null, ProfileData.class);
    }

    public void removeProfile(String profileID) throws Exception {
        delete(profileID, Void.class);
    }
}
