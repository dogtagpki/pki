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
package com.netscape.cms.profile.constraint;


import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.apps.*;

import com.netscape.cms.profile.def.*;


/**
 * This class implements no constraint.
 *
 * @version $Revision$, $Date$
 */
public class NoConstraint implements IPolicyConstraint {

    public static final String CONFIG_NAME = "name";

    private IConfigStore mConfig = null; 
    private Vector mNames = new Vector();

    public Enumeration getConfigNames() {
        return mNames.elements();
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    public void setConfig(String name, String value)
        throws EPropertyException {
    }

    public String getConfig(String name) {
        return null;
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    public void init(IProfile profile, IConfigStore config)
        throws EProfileException {
        mConfig = config;
    }

    public IConfigStore getConfigStore() {
        return mConfig;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     */
    public void validate(IRequest request)
        throws ERejectException {
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, 
                "CMS_PROFILE_CONSTRAINT_NO_CONSTRAINT_TEXT");
    }

    public String getName(Locale locale) {
        try {
            return mConfig.getString(CONFIG_NAME);
        } catch (EBaseException e) {
            return null;
        }
    }

    public boolean isApplicable(IPolicyDefault def) {
        return true;
    }
}
