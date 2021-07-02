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
//(C) 2011 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---

package com.netscape.certsrv.profile;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.netscape.certsrv.util.JSONSerializer;

/**
 * @author alee
 *
 */
@JsonInclude(Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
public class ProfileDataInfo implements JSONSerializer {

    protected String profileURL;

    protected String profileId;

    protected String profileName;

    protected String profileDescription;

    public ProfileDataInfo() {
        // required for JAXB (defaults)
    }

    /**
     * @return the profileURL
     */
    public String getProfileURL() {
        return profileURL;
    }

    /**
     * @param profileURL the profileURL to set
     */
    public void setProfileURL(String profileURL) {
        this.profileURL = profileURL;
    }

    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

    /**
     * @return the profile ID in the profileURL
     */
    public String getProfileId() {
        return profileId;
    }

    public String getProfileName() {
        return profileName;
    }

    public void setProfileName(String profileName) {
        this.profileName = profileName;
    }

    public String getProfileDescription() {
        return profileDescription;
    }

    public void setProfileDescription(String profileDescription) {
        this.profileDescription = profileDescription;
    }

    @Override
    public int hashCode() {
        return Objects.hash(profileDescription, profileId, profileName, profileURL);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ProfileDataInfo other = (ProfileDataInfo) obj;
        return Objects.equals(profileDescription, other.profileDescription)
                && Objects.equals(profileId, other.profileId) && Objects.equals(profileName, other.profileName)
                && Objects.equals(profileURL, other.profileURL);
    }

}
