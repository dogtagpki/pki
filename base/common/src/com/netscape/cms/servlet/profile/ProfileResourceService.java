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

package com.netscape.cms.servlet.profile;

import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.profile.model.ProfileDAO;
import com.netscape.cms.servlet.profile.model.ProfileData;
import com.netscape.cms.servlet.profile.model.ProfileDataInfos;

/**
 * @author alee
 *
 */
public class ProfileResourceService extends CMSResourceService implements ProfileResource {
    @Override
    public ProfileData retrieveProfile(String id) {
        ProfileData data = null;
        ProfileDAO dao = new ProfileDAO();
        data = dao.getProfile(id);
        return data;
    }

    public ProfileDataInfos listProfiles() {
        ProfileDAO dao = new ProfileDAO();
        return dao.listProfiles(uriInfo);
    }
}
