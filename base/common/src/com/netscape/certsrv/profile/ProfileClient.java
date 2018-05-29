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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.base.PKIException;
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
        Response response = profileClient.retrieveProfile(id);
        return client.getEntity(response, ProfileData.class);
    }

    public byte[] retrieveProfileRaw(String id) {
        Response response = profileClient.retrieveProfileRaw(id);
        return client.getEntity(response, byte[].class);
    }

    public ProfileDataInfos listProfiles(Integer start, Integer size) {
        Response response =  profileClient.listProfiles(start, size);
        return client.getEntity(response, ProfileDataInfos.class);
    }

    public void enableProfile(String id) {
        Response response = profileClient.modifyProfileState(id, "enable");
        client.getEntity(response, Void.class);
    }

    public void disableProfile(String id) {
        Response response = profileClient.modifyProfileState(id, "disable");
        client.getEntity(response, Void.class);
    }

    public ProfileData createProfile(ProfileData data) {
        Response response = profileClient.createProfile(data);
        return client.getEntity(response, ProfileData.class);
    }

    public byte[] createProfileRaw(byte[] properties) {
        Response response =
            profileClient.createProfileRaw(properties);
        return client.getEntity(response, byte[].class);
    }

    public ProfileData modifyProfile(ProfileData data) {
        Response response = profileClient.modifyProfile(data.getId(), data);
        return client.getEntity(response, ProfileData.class);
    }

    public byte[] modifyProfileRaw(String profileId, byte[] properties) {
        Response response =
            profileClient.modifyProfileRaw(profileId, properties);
        return client.getEntity(response, byte[].class);
    }

    public void deleteProfile(String id) {
        Response response = profileClient.deleteProfile(id);
        client.getEntity(response, Void.class);
    }

}
