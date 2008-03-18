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
package com.netscape.certsrv.profile;

import java.util.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.request.*;

/**
 * This interface represents a input policy which
 * provides information on how to create the
 * end-user enrollment page.
 * 
 * @version $Revision: 14561 $, $Date: 2007-05-01 10:28:56 -0700 (Tue, 01 May 2007) $
 */
public interface IProfileInput extends IConfigTemplate {

    /**
     * Initializes this default policy.
     *
     * @param profile owner of this input
     * @param config configuration store
     * @exception EProfileException failed to initialize
     */
    public void init(IProfile profile, IConfigStore config)
        throws EProfileException;

    /**
     * Returns configuration store.
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore();

    /**
     * Populates the request with this policy default.
     *
     * @param ctx profile context
     * @param request request
     * @exception EProfileException failed to populate
     */
    public void populate(IProfileContext ctx, IRequest request)
        throws EProfileException;

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale user locale
     * @return localized input name
     */
    public String getName(Locale locale);

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale user locale
     * @return localized input description
     */
    public String getText(Locale locale);

    /**
     * Retrieves a list of names of the property.
     *
     * @return a list of property names
     */
    public Enumeration getValueNames();

    /**
     * Retrieves the descriptor of the given value 
     * property by name.
     *
     * @param locale user locale
     * @param name property name
     * @return descriptor of the property
     */
    public IDescriptor getValueDescriptor(Locale locale, String name);

    /**
     * Retrieves value from the request.
     *
     * @param name property name
     * @param locale user locale
     * @param request request
     * @exception EProfileException failed to get value
     */
    public String getValue(String name, Locale locale, IRequest request)
        throws EProfileException;

    /**
     * Sets the value of the given property by name.
     *
     * @param name property name
     * @param locale user locale
     * @param request request
     * @param value value
     * @exception EProfileException failed to get value
     */
    public void setValue(String name, Locale locale, IRequest request, 
        String value) throws EPropertyException;
}
