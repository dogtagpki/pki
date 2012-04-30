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
package com.netscape.cms.servlet.profile.model;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.ws.rs.Path;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileInput;
import com.netscape.certsrv.profile.IProfileSubsystem;
import com.netscape.cms.servlet.profile.ProfileNotFoundException;
import com.netscape.cms.servlet.profile.ProfileResource;

/**
 * @author alee
 *
 */
public class ProfileDAO {

    private IProfileSubsystem ps;

    public ProfileDAO() {
        ps = (IProfileSubsystem) CMS.getSubsystem(IProfileSubsystem.ID);
    }

    /**
     * Returns list of profiles
     */

    public ProfileDataInfos listProfiles(UriInfo uriInfo)
    {

        List<ProfileDataInfo> list = new ArrayList<ProfileDataInfo>();
        ProfileDataInfos infos = new ProfileDataInfos();

        if (ps == null) {
            return null;
        }

        Enumeration<String> profileIds = ps.getProfileIds();

        if (profileIds != null) {
            while (profileIds.hasMoreElements()) {
                String id = profileIds.nextElement();
                ProfileDataInfo info = null;
                try {
                    info = createProfileDataInfo(id, uriInfo);
                } catch (EBaseException e) {
                    continue;
                }

                if (info != null) {
                    list.add(info);
                }
            }
        }

        infos.setProfileInfos(list);

        return infos;
    }

    public ProfileData getProfile(String profileId) throws ProfileNotFoundException {
        ProfileData data = null;

        if (ps == null) {
            return null;
        }

        Enumeration<String> profileIds = ps.getProfileIds();

        IProfile profile = null;
        if (profileIds != null) {
            while (profileIds.hasMoreElements()) {
                String id = profileIds.nextElement();

                if (id.equals(profileId)) {

                    try {
                        profile = ps.getProfile(profileId);
                    } catch (EProfileException e) {
                        e.printStackTrace();
                        throw new ProfileNotFoundException(profileId);
                    }
                    break;
                }
            }
        }

        if (profile == null) {
            throw new ProfileNotFoundException(profileId);
        }

        try {
            data = createProfileData(profileId);
        } catch (EBaseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            throw new ProfileNotFoundException(profileId);
        }

        return data;
    }

    public ProfileData createProfileData(String profileId) throws EBaseException {

        IProfile profile;

        try {
            profile = ps.getProfile(profileId);
        } catch (EProfileException e) {
            e.printStackTrace();
            throw new ProfileNotFoundException(profileId);
        }

        ProfileData data = new ProfileData();

        Locale locale = Locale.getDefault();
        String name = profile.getName(locale);
        String desc = profile.getDescription(locale);

        data.setName(name);
        data.setDescription(desc);
        data.setIsEnabled(ps.isProfileEnable(profileId));
        data.setIsVisible(profile.isVisible());
        data.setEnabledBy(ps.getProfileEnableBy(profileId));
        data.setId(profileId);

        Enumeration<String> inputIds = profile.getProfileInputIds();

        String inputName = null;

        if (inputIds != null) {
            while (inputIds.hasMoreElements()) {
                String inputId = inputIds.nextElement();
                IProfileInput profileInput = profile.getProfileInput(inputId);

                if (profileInput == null) {
                    continue;
                }
                inputName = profileInput.getName(locale);

                Enumeration<String> inputNames = profileInput.getValueNames();

                ProfileInput input = data.addProfileInput(inputName);

                String curInputName = null;
                while (inputNames.hasMoreElements()) {
                    curInputName = inputNames.nextElement();

                    if (curInputName != null && !curInputName.equals("")) {
                        input.setInputAttr(curInputName, "");
                    }

                }
            }
        }

        return data;

    }

    public ProfileDataInfo createProfileDataInfo(String profileId, UriInfo uriInfo) throws EBaseException {

        if (profileId == null) {
            throw new EBaseException("Error creating ProfileDataInfo.");
        }
        ProfileDataInfo ret = null;

        IProfile profile = null;

        profile = ps.getProfile(profileId);
        if (profile == null) {
            return null;
        }

        ret = new ProfileDataInfo();

        ret.setProfileId(profileId);

        Path profilePath = ProfileResource.class.getAnnotation(Path.class);

        UriBuilder profileBuilder = uriInfo.getBaseUriBuilder();
        profileBuilder.path(profilePath.value() + "/" + profileId);
        ret.setProfileURL(profileBuilder.build().toString());

        return ret;
    }

}