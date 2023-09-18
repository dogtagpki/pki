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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.PolicyDefaultConfig;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.request.Request;

/**
 * This class implements no default policy.
 *
 * @version $Revision$, $Date$
 */
public class NoDefault extends PolicyDefault {

    protected Vector<String> mValues = new Vector<>();
    protected Vector<String> mNames = new Vector<>();

    @Override
    public Enumeration<String> getConfigNames() {
        return mNames.elements();
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    @Override
    public String getConfig(String name) {
        return null;
    }

    @Override
    public PolicyDefaultConfig getConfigStore() {
        return mConfig;
    }

    /**
     * Populates the request with this policy default.
     */
    @Override
    public void populate(Request request)
            throws EProfileException {
    }

    @Override
    public Enumeration<String> getValueNames() {
        return mValues.elements();
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public void setValue(String name, Locale locale, Request request,
            String value)
            throws EPropertyException {
    }

    @Override
    public String getValue(String name, Locale locale, Request request) {
        return null;
    }

    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_PROFILE_DEF_NO_DEFAULT");
    }

    @Override
    public String getName(Locale locale) {
        try {
            return mConfig.getDefaultName();
        } catch (EBaseException e) {
            return null;
        }
    }
}
