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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.profile;

import com.netscape.certsrv.base.ResourceNotFoundException;

public class ProfileNotFoundException extends ResourceNotFoundException {

    private static final long serialVersionUID = -4784839378360933483L;

    public String profileId;

    public ProfileNotFoundException(String profileId) {
        this(profileId, "Profile ID " + profileId + " not found");
    }

    public ProfileNotFoundException(String profileId, String message) {
        super(message);
        this.profileId = profileId;
    }

    public ProfileNotFoundException(String profileId, String message, Throwable cause) {
        super(message, cause);
        this.profileId = profileId;
    }

    public ProfileNotFoundException(Data data) {
        super(data);
        profileId = data.getAttribute("profileId");
    }

    public Data getData() {
        Data data = super.getData();
        data.setAttribute("profileId", profileId);
        return data;
    }

    public String getProfileId() {
        return profileId;
    }

    public void setRequestId(String profileId) {
        this.profileId = profileId;
    }
}
