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


import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.property.*;


/**
 * This class implements the basic enrollment output.
 *
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public abstract class EnrollOutput implements IProfileOutput { 
    private IConfigStore mConfig = null;
    private Vector mValueNames = new Vector();
    protected Vector mConfigNames = new Vector();
 
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
    public Enumeration getValueNames() {
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

    public Enumeration getConfigNames() {
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
