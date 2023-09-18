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

import org.dogtagpki.server.ca.CAEngineConfig;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IConfigTemplate;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cms.profile.common.PolicyDefaultConfig;
import com.netscape.cmscore.request.Request;

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
public abstract class PolicyDefault implements IConfigTemplate {

    protected CAEngineConfig engineConfig;
    protected PolicyDefaultConfig mConfig;

    /**
     * Initializes this default policy.
     *
     * @param engineConfig engine configuration
     * @param config configuration store for this default
     * @exception EProfileException failed to initialize
     */
    public void init(CAEngineConfig engineConfig, PolicyDefaultConfig config) throws EProfileException {
        this.engineConfig = engineConfig;
        this.mConfig = config;
    }

    /**
     * Retrieves the configuration store of this default.
     *
     * @return configuration store of this default policy
     */
    public abstract PolicyDefaultConfig getConfigStore();

    /**
     * Populates the request with this policy default.
     *
     * @param request request to be populated
     * @exception EProfileException failed to populate
     */
    public abstract void populate(Request request)
            throws EProfileException;

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale locale of the end user
     * @return localized name of this default policy
     */
    public abstract String getName(Locale locale);

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale locale of the end user
     * @return localized description of this default policy
     */
    public abstract String getText(Locale locale);

    /**
     * Retrieves a list of names of the property.
     *
     * @return a list of property names. The values are
     *         of type java.lang.String
     */
    public abstract Enumeration<String> getValueNames();

    /**
     * Retrieves the descriptor of the given property
     * by name. The descriptor contains syntax
     * information.
     *
     * @param locale locale of the end user
     * @param name name of property
     * @return descriptor of the property
     */
    public abstract IDescriptor getValueDescriptor(Locale locale, String name);

    /**
     * Sets the value of the given value property by name.
     *
     * @param name name of property
     * @param locale locale of the end user
     * @param request request
     * @param value value to be set in the given request
     * @exception EPropertyException failed to set property
     */
    public abstract void setValue(String name, Locale locale, Request request,
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
    public abstract String getValue(String name, Locale locale, Request request)
            throws EPropertyException;

}
