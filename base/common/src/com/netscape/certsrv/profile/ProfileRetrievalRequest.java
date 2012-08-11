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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

/**
 *
 */
package com.netscape.certsrv.profile;

import javax.ws.rs.core.MultivaluedMap;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author alee
 *
 */
@XmlRootElement(name = "ProfileRetrievalRequest")
@XmlAccessorType(XmlAccessType.FIELD)
public class ProfileRetrievalRequest {

    private static final String PROFILE_ID = "profileId";

    @XmlElement
    protected String profileId;

    public ProfileRetrievalRequest() {
        // required for JAXB (defaults)
    }

    public ProfileRetrievalRequest(MultivaluedMap<String, String> form) {
        if (form.containsKey(PROFILE_ID)) {
            profileId = form.getFirst(PROFILE_ID);
        }
    }

    /**
     * @return the ProfileId
     */
    public String getProfileId() {
        return profileId;
    }

    /**
     * @param ProfileId the ProfileId to set
     */
    public void setProfileId(String profileId) {
        this.profileId = profileId;
    }

}