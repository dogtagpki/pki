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
package com.netscape.cms.profile.input;


import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;


/**
 * This class implements the image
 * input that collects a picture.
 * <p>
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public class ImageInput extends EnrollInput implements IProfileInput { 

    public static final String IMAGE_URL = "image_url";

    public ImageInput() {
        addValueName(IMAGE_URL);
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
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_IMAGE_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_IMAGE_TEXT");
    }

    /**
     * Populates the request with this policy default.
     */
    public void populate(IProfileContext ctx, IRequest request)
        throws EProfileException {
        request.setExtData(IMAGE_URL, ctx.get(IMAGE_URL));
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(IMAGE_URL)) {
            return new Descriptor(IDescriptor.STRING, null,
                    null,
                    CMS.getUserMessage(locale, "CMS_PROFILE_INPUT_IMAGE_URL"));
        }
        return null;
    }
}
