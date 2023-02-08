// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.tps.profile;

import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.certsrv.util.StringHashMapValueDeserializer;

/**
 * @author Endi S. Dewata
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ProfileMappingData implements JSONSerializer {

    String id;
    String profileMappingID;
    String status;
    @JsonDeserialize(using = StringHashMapValueDeserializer.class)
    Map<String, String> properties;

    public String getID() {
        return id;
    }

    public void setID(String id) {
        this.id = id;
    }

    @JsonProperty("ProfileMappingID")
    public String getProfileMappingID() {
        return profileMappingID;
    }

    public void setProfileMappingID(String profileMappingID) {
        this.profileMappingID = profileMappingID;
    }

    @JsonProperty("Status")
    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @JsonProperty("Properties")
    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, profileMappingID, properties, status);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ProfileMappingData other = (ProfileMappingData) obj;
        return Objects.equals(id, other.id) &&
                Objects.equals(profileMappingID, other.profileMappingID) &&
                Objects.equals(properties, other.properties) &&
                Objects.equals(status, other.status);
    }

    @Override
    public String toString() {
        try {
            return toJSON();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
