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
package com.netscape.certsrv.ca;

import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.NameValuePairs;

/**
 * An interface representing a list of CRL extensions.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface ICMSCRLExtensions {

    /**
     * Updates configuration store for extension identified by id with data
     * delivered in name value pairs.
     * 
     * @param id extension id
     * @param nvp name value pairs with new configuration data
     * @param config configuration store
     */
    public void setConfigParams(String id, NameValuePairs nvp,
            IConfigStore config);

    /**
     * Reads configuration data and returns them as name value pairs.
     * 
     * @param id extension id
     * @return name value pairs with configuration data
     */
    public NameValuePairs getConfigParams(String id);

    /**
     * Returns class name with its path.
     * 
     * @param name extension id
     * @return class name with its path
     */
    public String getClassPath(String name);
}
