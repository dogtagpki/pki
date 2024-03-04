/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.topology;

import com.netscape.management.client.console.*;


/**
 * Defines capabilities for a server product.  This interface
 * should be implemented by a server product instance node that
 * supports create new instance functionality.
 *
 * @author  phlee
 * @see     IServerObject
 */
public interface IProductObject {

    /**
     * Initialize server object with system information such as directory
     * server location, port number, etc. Called by the topology code after
     * object construction.
     *
     * @param  info - global information
     */
    public void initialize(ConsoleInfo info);


    /**
     * Starts the server specific creation code, providing the DN for the
     * target admin group. The method returns true or false depending
     * on whether it was successful.
     *
     * @param  targetDN - the admin group DN where the new instance is to be
     *                    created.
     * @return  boolean value indicating whether the process succeeded (true)
     *          or failed (false).
     */
    public boolean createNewInstance(String targetDN);
}
