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
package com.netscape.cms.profile.def;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements no default policy.
 *
 * @version $Revision$, $Date$
 */
public class NoDefault implements IPolicyDefault {

    public static final String PROP_NAME = "name";

    protected Vector<String> mValues = new Vector<String>();
    protected Vector<String> mNames = new Vector<String>();
    protected IConfigStore mConfig = null;

    public Enumeration<String> getConfigNames() {
        return mNames.elements();
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    public void setConfig(String name, String value)
            throws EPropertyException {
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    public String getConfig(String name) {
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
     * Populates the request with this policy default.
     */
    public void populate(IRequest request)
            throws EProfileException {
    }

    public Enumeration<String> getValueNames() {
        return mValues.elements();
    }

    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public void setValue(String name, Locale locale, IRequest request,
            String value)
            throws EPropertyException {
    }

    public String getValue(String name, Locale locale, IRequest request) {
        return null;
    }

    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_NO_DEFAULT");
    }

    public String getName(Locale locale) {
        try {
            return mConfig.getString(PROP_NAME);
        } catch (EBaseException e) {
            return null;
        }
    }
}
