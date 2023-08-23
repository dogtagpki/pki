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
package com.netscape.cms.profile.output;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.ProfileOutput;
import com.netscape.cms.profile.common.ProfileOutputConfig;
import com.netscape.cmscore.request.Request;

/**
 * This class implements the basic enrollment output.
 *
 * @version $Revision$, $Date$
 */
public abstract class EnrollOutput extends ProfileOutput {
    private ProfileOutputConfig mConfig;
    private Vector<String> mValueNames = new Vector<>();
    protected Vector<String> mConfigNames = new Vector<>();

    /**
     * Initializes this default policy.
     */
    @Override
    public void init(ProfileOutputConfig config) throws EProfileException {
        mConfig = config;
    }

    @Override
    public ProfileOutputConfig getConfigStore() {
        return mConfig;
    }

    public void addValueName(String name) {
        mValueNames.addElement(name);
    }

    /**
     * Populates the request with this policy default.
     *
     * @param ctx profile context
     * @param request request
     * @exception EProfileException failed to populate
     */
    @Override
    public abstract void populate(Map<String, String> ctx, Request request)
            throws EProfileException;

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     *
     * @param locale user locale
     * @param name property name
     * @return property descriptor
     */
    @Override
    public abstract IDescriptor getValueDescriptor(Locale locale, String name);

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale user locale
     * @return output policy name
     */
    @Override
    public abstract String getName(Locale locale);

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale user locale
     * @return output policy description
     */
    @Override
    public abstract String getText(Locale locale);

    /**
     * Retrieves a list of names of the value parameter.
     */
    @Override
    public Enumeration<String> getValueNames() {
        return mValueNames.elements();
    }

    @Override
    public String getValue(String name, Locale locale, Request request)
            throws EProfileException {
        return request.getExtDataInString(name);
    }

    /**
     * Sets the value of the given value parameter by name.
     */
    @Override
    public void setValue(String name, Locale locale, Request request,
            String value) throws EPropertyException {
        request.setExtData(name, value);
    }

    @Override
    public Enumeration<String> getConfigNames() {
        return mConfigNames.elements();
    }

    @Override
    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        return null;
    }

    @Override
    public void setConfig(String name, String value)
            throws EPropertyException {
    }

    @Override
    public String getConfig(String name) {
        return null;
    }

    public String getDefaultConfig(String name) {
        return null;
    }
}
