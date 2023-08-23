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
// (C) 2020 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.profile.input;

import java.util.Locale;
import java.util.Map;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.Profile;
import com.netscape.cms.profile.common.ProfileInputConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements input for the Server-Side Keygen Enrollment
 * <p>
 *
 * @author Christina Fu
 */
public class ServerKeygenInput extends EnrollInput {

    public static final String P12PASSWORD = "serverSideKeygenP12Passwd";

    public static final String KEY_TYPE = "keyType";
    public static final String KEY_SIZE = "keySize";


    public ServerKeygenInput() {
        addValueName(P12PASSWORD);

        addValueName(KEY_TYPE);
        addValueName(KEY_SIZE);

    }

    /**
     * Initializes this default policy.
     */
    @Override
    public void init(Profile profile, ProfileInputConfig config) throws EProfileException {
        super.init(profile, config);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SERVER_KEYGEN_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SERVER_KEYGEN_TEXT");
    }

    @Override
    public String getConfig(String name) {
        String config = super.getConfig(name);
        if (config == null || config.equals(""))
            return "true";
        return config;
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Map<String, String> ctx, Request request)
            throws EProfileException {
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(P12PASSWORD)) {
            return new Descriptor(IDescriptor.SERVER_SIDE_KEYGEN_REQUEST_TYPE, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SERVER_KEYGEN_P12PASSWD"));
        } else if (name.equals(KEY_TYPE)) {
            return new Descriptor(IDescriptor.SERVER_SIDE_KEYGEN_KEY_TYPE, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SERVER_KEYGEN_KEY_TYPE"));
        } else if (name.equals(KEY_SIZE)) {
            return new Descriptor(IDescriptor.SERVER_SIDE_KEYGEN_KEY_SIZE, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_SERVER_KEYGEN_KEY_SIZE"));
        }
        return null;
    }
}
