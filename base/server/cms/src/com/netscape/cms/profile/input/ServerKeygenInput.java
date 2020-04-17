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

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileInput;

/**
 * This class implements input for the Server-Side Keygen Enrollment
 * <p>
 *
 * @author Christina Fu
 */
public class ServerKeygenInput extends EnrollInput implements IProfileInput {

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
    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SERVER_KEYGEN_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_SERVER_KEYGEN_TEXT");
    }

    public String getConfig(String name) {
        String config = super.getConfig(name);
        if (config == null || config.equals(""))
            return "true";
        return config;
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IProfileContext ctx, IRequest request)
            throws EProfileException {
        //
        CMS.debug("ServerKeygenP12PasswordInput:populate: cfu");
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
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
