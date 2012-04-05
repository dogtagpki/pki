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
import java.util.Vector;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileContext;
import com.netscape.certsrv.profile.IProfileOutput;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This class implements the basic enrollment output.
 *
 * @version $Revision$, $Date$
 */
public abstract class EnrollOutput implements IProfileOutput {
    private IConfigStore mConfig = null;
    private Vector<String> mValueNames = new Vector<String>();
    protected Vector<String> mConfigNames = new Vector<String>();

    /**
     * Initializes this default policy.
     */
    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        mConfig = config;
    }

    public IConfigStore getConfigStore() {
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
    public abstract void populate(IProfileContext ctx, IRequest request)
            throws EProfileException;

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     *
     * @param locale user locale
     * @param name property name
     * @return property descriptor
     */
    public abstract IDescriptor getValueDescriptor(Locale locale, String name);

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale user locale
     * @return output policy name
     */
    public abstract String getName(Locale locale);

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale user locale
     * @return output policy description
     */
    public abstract String getText(Locale locale);

    /**
     * Retrieves a list of names of the value parameter.
     */
    public Enumeration<String> getValueNames() {
        return mValueNames.elements();
    }

    public String getValue(String name, Locale locale, IRequest request)
            throws EProfileException {
        return request.getExtDataInString(name);
    }

    /**
     * Sets the value of the given value parameter by name.
     */
    public void setValue(String name, Locale locale, IRequest request,
            String value) throws EPropertyException {
        request.setExtData(name, value);
    }

    public Enumeration<String> getConfigNames() {
        return mConfigNames.elements();
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
}
