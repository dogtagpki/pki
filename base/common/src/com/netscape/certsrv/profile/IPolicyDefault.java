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

import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IConfigTemplate;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * This represents a default policy that populates
 * the request with additional values.
 * <p>
 *
 * During request submission process, a default policy is invoked to populate the default values in the request. The
 * default values will later on be used for execution. The default values are like the parameters for the request.
 * <p>
 *
 * This policy is called in 2 places. For automated enrollment request, this policy is invoked to populate the HTTP
 * parameters into the request. For request that cannot be executed immediately, this policy will be invoked again right
 * after the agent's approval.
 * <p>
 *
 * Each default policy may contain zero or more properties that describe the default value. For example, a X509 Key can
 * be described by its key type, key length, and key data. The properties help to describe the default value into human
 * readable values.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface IPolicyDefault extends IConfigTemplate {

    /**
     * Initializes this default policy.
     *
     * @param profile owner of this default policy
     * @param config configuration store for this default
     * @exception EProfileException failed to initialize
     */
    public void init(IProfile profile, IConfigStore config)
            throws EProfileException;

    /**
     * Retrieves the configuration store of this default.
     *
     * @return configuration store of this default policy
     */
    public IConfigStore getConfigStore();

    /**
     * Populates the request with this policy default.
     *
     * @param request request to be populated
     * @exception EProfileException failed to populate
     */
    public void populate(IRequest request)
            throws EProfileException;

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale locale of the end user
     * @return localized name of this default policy
     */
    public String getName(Locale locale);

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale locale of the end user
     * @return localized description of this default policy
     */
    public String getText(Locale locale);

    /**
     * Retrieves a list of names of the property.
     *
     * @return a list of property names. The values are
     *         of type java.lang.String
     */
    public Enumeration<String> getValueNames();

    /**
     * Retrieves the descriptor of the given property
     * by name. The descriptor contains syntax
     * information.
     *
     * @param locale locale of the end user
     * @param name name of property
     * @return descriptor of the property
     */
    public IDescriptor getValueDescriptor(Locale locale, String name);

    /**
     * Sets the value of the given value property by name.
     *
     * @param name name of property
     * @param locale locale of the end user
     * @param request request
     * @param value value to be set in the given request
     * @exception EPropertyException failed to set property
     */
    public void setValue(String name, Locale locale, IRequest request,
            String value) throws EPropertyException;

    /**
     * Retrieves the value of the given value
     * property by name.
     *
     * @param name name of property
     * @param locale locale of the end user
     * @param request request
     * @exception EPropertyException failed to get property
     */
    public String getValue(String name, Locale locale, IRequest request)
            throws EPropertyException;

}
