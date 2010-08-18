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
package com.netscape.certsrv.property;


import java.util.*;


/**
 * This interface provides a standard way to describe
 * a set of configuration parameters and its associated syntax.
 * It provides programmatic methods for querying 
 * template description.
 * <p>
 * A plugin, for example, can be described as a
 * property template. 
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface IConfigTemplate {

    /**
     * Returns a list of configuration parameter names.
     * 
     * @return parameter names
     */
    public Enumeration getConfigNames();

    /**
     * Returns the descriptors of configuration parameter.
     *
     * @param locale user locale
     * @param name configuration parameter name
     * @return descriptor
     */
    public IDescriptor getConfigDescriptor(Locale locale, String name);

    /**
     * Sets configuration parameter.
     *
     * @param name parameter name
     * @param value parameter value
     * @exception EPropertyException failed to set parameter
     */
    public void setConfig(String name, String value)
        throws EPropertyException;

    /**
     * Retrieves configuration parameter by name.
     *
     * @return parameter
     */
    public String getConfig(String name);
}
