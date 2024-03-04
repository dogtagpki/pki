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

import com.netscape.management.client.*;
import com.netscape.management.client.console.*;


/**
 * Defines base level functionality for a server instance object.
 * Each server is required to implement this interface, otherwise
 * it will not appear in the topology tree.
 *
 * @author phlee
 */
public interface IServerObject extends IResourceObject {

    // TODO: description for each status type
    public static final int STATUS_UNKNOWN = 0;
    public static final int STATUS_STARTED = 1;
    public static final int STATUS_STOPPED = 2;
    public static final int STATUS_ALERT = 3;
    public static final int STATUS_NOT_SUPPORTED = 4;


    /**
     * Initialize server object with system information such as directory
     * server location, port number, etc. Called by the topology code after
     * object construction.
     *
     * @param  info - global information
     */
    public void initialize(ConsoleInfo info);


    /**
     * Returns the STATUS_* constant representing server state.
     * This routine need to update the last known status of the server.
     *
     * @return  int - STATUS_* constant representing server state.
     */
    public int getServerStatus();

    /**
     * The concrete class implementing this method will clone its
     * configuration from the reference server. This supports using the
      * GET method for cloning the server.
     *
     * @param  referenceDN - DN of server to clone from.
     */
    public void cloneFrom(String referenceDN);
}
