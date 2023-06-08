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

import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.client.Entity;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Ade Lee
 */
public class ProfileClient extends Client {

    public ProfileClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "profiles");
    }

    public ProfileData retrieveProfile(String id) throws Exception {
        return get(id, ProfileData.class);
    }

    public byte[] retrieveProfileRaw(String id) throws Exception {
        return get(id + "/raw", byte[].class);
    }

    public ProfileDataInfos listProfiles(Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, ProfileDataInfos.class);
    }

    public void enableProfile(String id) throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("action", "enable");
        post(id, params, null, Void.class);
    }

    public void disableProfile(String id) throws Exception {
        Map<String, Object> params = new HashMap<>();
        params.put("action", "disable");
        post(id, params, null, Void.class);
    }

    public ProfileData createProfile(ProfileData data) throws Exception {
        String createProfileRequest = (String) client.marshall(data);
        Entity<String> entity = client.entity(createProfileRequest);
        return post(null, null, entity, ProfileData.class);
    }

    public byte[] createProfileRaw(byte[] properties) throws Exception {
        Entity<byte[]> entity = client.entity(properties);
        return post("raw", null, entity, byte[].class);
    }

    public ProfileData modifyProfile(ProfileData data) throws Exception {
        String modifyProfileRequest = (String) client.marshall(data);
        Entity<String> entity = client.entity(modifyProfileRequest);
        return put(data.getId(), null, entity, ProfileData.class);
    }

    public byte[] modifyProfileRaw(String profileId, byte[] properties) throws Exception {
        Entity<byte[]> entity = client.entity(properties);
        return put(profileId + "/raw", null, entity, byte[].class);
    }

    public void deleteProfile(String id) throws Exception {
        delete(id, Void.class);
    }
}
